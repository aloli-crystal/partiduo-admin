# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"
require "webauthn"

module PartiduoAdmin
  module Auth
    # Passkeys par `prod-crystal/webauthn` (ADR-002 D2) : credential
    # découvrable, vérification de l'utilisateur exigée, attestation `none`,
    # RP ID = nom d'hôte de l'administration. Niveau 3, exigé du super-admin.
    module Passkeys
      PURPOSE_CREATE = "webauthn.create"
      PURPOSE_GET    = "webauthn.get"

      class Error < Exception
        getter key : String

        def initialize(@key : String, message : String? = nil)
          super(message || key)
        end
      end

      def self.user_handle(user : User) : Bytes
        digest = OpenSSL::Digest.new("SHA256")
        digest.update("partiduo-admin:#{Config.rp_id}:#{user.pk}")
        digest.final[0, 16]
      end

      # Options de `navigator.credentials.create()` (JSON, octets en
      # base64url) et poignée du défi.
      def self.registration_options(user : User) : {String, String}
        challenge = Secrets.base64url(WebAuthn.generate_challenge)
        issued = Challenges.issue(PURPOSE_CREATE, user: user, value: challenge)
        excluded = Passkey.filter(user_id: user.pk).map { |key| {"type" => "public-key", "id" => key.credential_id.to_s} }
        options = {
          "challengeId" => issued.handle,
          "publicKey"   => {
            "challenge" => challenge,
            "rp"        => {"id" => Config.rp_id, "name" => Config::ISSUER},
            "user"      => {
              "id"          => Secrets.base64url(user_handle(user)),
              "name"        => user.email.to_s,
              "displayName" => user.display_name,
            },
            "pubKeyCredParams"       => WebAuthn::COSE::DEFAULT_ALGORITHMS.map { |alg| {"type" => "public-key", "alg" => alg} },
            "timeout"                => Config::CHALLENGE_TIMEOUT.total_milliseconds.to_i,
            "attestation"            => "none",
            "excludeCredentials"     => excluded,
            "authenticatorSelection" => {"residentKey" => "required", "userVerification" => "required"},
          },
        }
        {options.to_json, challenge}
      end

      def self.authentication_options(user : User? = nil) : {String, String}
        challenge = Secrets.base64url(WebAuthn.generate_challenge)
        issued = Challenges.issue(PURPOSE_GET, user: user, value: challenge)
        allowed = user ? Passkey.filter(user_id: user.pk).map { |key| {"type" => "public-key", "id" => key.credential_id.to_s} } : [] of Hash(String, String)
        options = {
          "challengeId" => issued.handle,
          "publicKey"   => {
            "challenge"        => challenge,
            "rpId"             => Config.rp_id,
            "timeout"          => Config::CHALLENGE_TIMEOUT.total_milliseconds.to_i,
            "userVerification" => "required",
            "allowCredentials" => allowed,
          },
        }
        {options.to_json, challenge}
      end

      def self.finish_registration(user : User, handle : String, attestation_object : String,
                                   client_data_json : String, name : String) : Passkey
        challenge = Challenges.consume(PURPOSE_CREATE, handle)
        raise Error.new("admin.errors.passkey.challenge") if challenge.nil? || challenge.user_id != user.pk
        attestation = decode(attestation_object)
        client_data = decode(client_data_json)
        credential = begin
          relying_party(client_data).verify_registration(attestation, client_data, decode(challenge.value.to_s),
            user_verification: WebAuthn::UserVerification::Required)
        rescue ex : WebAuthn::Error
          raise Error.new("admin.errors.passkey.invalid", ex.message)
        end
        credential_id = Secrets.base64url(credential.id)
        raise Error.new("admin.errors.passkey.already_registered") if Passkey.filter(credential_id: credential_id).exists?
        Passkey.create!(
          user: user,
          credential_id: credential_id,
          public_key: Base64.strict_encode(cose_key_bytes(attestation)),
          cose_algorithm: credential.public_key.cose_algorithm.to_i32,
          sign_count: credential.sign_count.to_i64,
          backup_eligible: credential.backup_eligible?,
          backup_state: credential.backup_state?,
          name: name.strip[0, 100]? || "",
        )
      end

      def self.finish_authentication(handle : String, credential_id : String, authenticator_data : String,
                                     client_data_json : String, signature : String,
                                     expected_user : User? = nil, now : Time = Time.utc) : User
        challenge = Challenges.consume(PURPOSE_GET, handle)
        raise Error.new("admin.errors.passkey.challenge") if challenge.nil?
        id_bytes = decode(credential_id)
        passkey = Passkey.filter(credential_id: Secrets.base64url(id_bytes)).first
        raise Error.new("admin.errors.passkey.unknown") if passkey.nil?
        user = passkey.user!
        if ((bound = challenge.user_id) && bound != user.pk) || (expected_user && expected_user.pk != user.pk)
          raise Error.new("admin.errors.passkey.unknown")
        end
        client_data = decode(client_data_json)
        stored = WebAuthn::Credential.new(
          id: id_bytes,
          public_key: WebAuthn::COSE.decode_key(Base64.decode(passkey.public_key.to_s), WebAuthn::COSE::DEFAULT_ALGORITHMS),
          sign_count: (passkey.sign_count || 0_i64).to_u32,
          aaguid: Bytes.new(WebAuthn::AuthenticatorData::AAGUID_SIZE),
          backup_eligible: passkey.backup_eligible == true,
          backup_state: passkey.backup_state == true,
          user_verified: true,
        )
        assertion = begin
          relying_party(client_data).verify_authentication(stored, decode(authenticator_data), client_data,
            decode(signature), decode(challenge.value.to_s), user_verification: WebAuthn::UserVerification::Required,
            credential_id: id_bytes)
        rescue ex : WebAuthn::Error
          raise Error.new("admin.errors.passkey.invalid", ex.message)
        end
        passkey.sign_count = assertion.sign_count.to_i64
        passkey.backup_state = assertion.backup_state?
        passkey.last_used_at = now
        passkey.save!
        user
      end

      private def self.relying_party(client_data : Bytes) : WebAuthn::RelyingParty
        origin = begin
          JSON.parse(String.new(client_data))["origin"]?.try(&.as_s?)
        rescue JSON::ParseException
          nil
        end
        raise Error.new("admin.errors.passkey.origin") if origin.nil? || !Config.origin_allowed?(origin)
        WebAuthn::RelyingParty.new(id: Config.rp_id, origins: [origin], algorithms: WebAuthn::COSE::DEFAULT_ALGORITHMS)
      end

      private def self.decode(value : String) : Bytes
        Secrets.decode64?(value) || raise Error.new("admin.errors.passkey.invalid", "base64url invalide")
      end

      private def self.cose_key_bytes(attestation : Bytes) : Bytes
        auth_data = WebAuthn::CBOR.decode_map(attestation)["authData"].as_bytes
        offset = WebAuthn::AuthenticatorData::FIXED_SIZE + WebAuthn::AuthenticatorData::AAGUID_SIZE
        length = (auth_data[offset].to_i << 8) | auth_data[offset + 1].to_i
        offset += 2 + length
        remaining = auth_data[offset, auth_data.size - offset]
        remaining[0, WebAuthn::CBOR.decode_first(remaining)[:size]].dup
      end
    end
  end
end
