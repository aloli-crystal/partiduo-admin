# SPDX-License-Identifier: AGPL-3.0-or-later

require "openssl"
require "jose"
require "webauthn"
require "json"

module AdminSpec
  # Authentificateur de plate-forme simulé (ES256), sur le modèle des specs
  # de partiduo-app : produit ce qu'enverrait `navigator.credentials`.
  class Authenticator
    getter key : Jose::JWK::ECKey
    getter credential_id : Bytes
    property sign_count : UInt32 = 0_u32

    def initialize
      @key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      @credential_id = Random::Secure.random_bytes(32)
    end

    def self.head(major : UInt8, n : Int) : Bytes
      io = IO::Memory.new
      value = n.to_u64
      if value < 24
        io.write_byte((major << 5) | value.to_u8)
      elsif value <= UInt8::MAX
        io.write_byte((major << 5) | 24_u8)
        io.write_byte(value.to_u8)
      else
        io.write_byte((major << 5) | 25_u8)
        io.write_byte((value >> 8).to_u8)
        io.write_byte((value & 0xff).to_u8)
      end
      io.to_slice
    end

    def self.int(value : Int) : Bytes
      value < 0 ? head(1_u8, -1 - value) : head(0_u8, value)
    end

    def self.bytes(data : Bytes) : Bytes
      join(head(2_u8, data.size), data)
    end

    def self.text(value : String) : Bytes
      join(head(3_u8, value.bytesize), value.to_slice)
    end

    def self.map(pairs : Array(Tuple(Bytes, Bytes))) : Bytes
      io = IO::Memory.new
      io.write(head(5_u8, pairs.size))
      pairs.each { |(key, value)| io.write(key); io.write(value) }
      io.to_slice
    end

    def self.join(*parts : Bytes) : Bytes
      io = IO::Memory.new
      parts.each { |part| io.write(part) }
      io.to_slice
    end

    def self.sha256(data : Bytes) : Bytes
      OpenSSL::Digest.new("SHA256").update(data).final
    end

    def self.b64(data : Bytes) : String
      Base64.urlsafe_encode(data, padding: false)
    end

    def cose_key : Bytes
      public = key.public_key
      A.map([{A.int(1), A.int(2)}, {A.int(3), A.int(-7)}, {A.int(-1), A.int(1)},
             {A.int(-2), A.bytes(public.x)}, {A.int(-3), A.bytes(public.y)}])
    end

    private alias A = Authenticator

    def authenticator_data(rp_id : String, flags : UInt8, attested : Bool) : Bytes
      io = IO::Memory.new
      io.write(A.sha256(rp_id.to_slice))
      io.write_byte(flags)
      4.times { |i| io.write_byte(((@sign_count >> ((3 - i) * 8)) & 0xff).to_u8) }
      if attested
        io.write(Bytes.new(16))
        io.write_byte(((@credential_id.size >> 8) & 0xff).to_u8)
        io.write_byte((@credential_id.size & 0xff).to_u8)
        io.write(@credential_id)
        io.write(cose_key)
      end
      io.to_slice
    end

    def client_data(type : String, challenge : String, origin : String) : Bytes
      %({"type":"#{type}","challenge":"#{challenge}","origin":"#{origin}","crossOrigin":false}).to_slice
    end

    UP_UV_AT = WebAuthn::AuthenticatorData::FLAG_USER_PRESENT | WebAuthn::AuthenticatorData::FLAG_USER_VERIFIED |
               WebAuthn::AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
    UP_UV = WebAuthn::AuthenticatorData::FLAG_USER_PRESENT | WebAuthn::AuthenticatorData::FLAG_USER_VERIFIED

    # Champs du formulaire d'enregistrement, à partir des options JSON.
    def register(options_json : String, origin : String = ORIGIN) : Hash(String, String)
      options = JSON.parse(options_json)
      public_key = options["publicKey"]
      auth_data = authenticator_data(public_key["rp"]["id"].as_s, UP_UV_AT, attested: true)
      attestation = A.map([{A.text("fmt"), A.text("none")}, {A.text("attStmt"), Bytes[0xa0]},
                           {A.text("authData"), A.bytes(auth_data)}])
      {
        "challenge_id"       => options["challengeId"].as_s,
        "attestation_object" => A.b64(attestation),
        "client_data_json"   => A.b64(client_data("webauthn.create", public_key["challenge"].as_s, origin)),
        "name"               => "Portable",
      }
    end

    # Champs du formulaire d'authentification.
    def assert(options_json : String, origin : String = ORIGIN) : Hash(String, String)
      options = JSON.parse(options_json)
      public_key = options["publicKey"]
      auth_data = authenticator_data(public_key["rpId"].as_s, UP_UV, attested: false)
      client = client_data("webauthn.get", public_key["challenge"].as_s, origin)
      signature = Jose::JWS.sign_data(A.join(auth_data, A.sha256(client)), Jose::JWS::Algorithm::ES256, @key)
      {
        "challenge_id"       => options["challengeId"].as_s,
        "credential_id"      => A.b64(@credential_id),
        "authenticator_data" => A.b64(auth_data),
        "client_data_json"   => A.b64(client),
        "signature"          => A.b64(signature),
      }
    end
  end
end
