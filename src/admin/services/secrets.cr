# SPDX-License-Identifier: AGPL-3.0-or-later

require "base64"
require "crypto/subtle"
require "openssl"

module PartiduoAdmin
  # Jetons aléatoires et empreintes : un jeton remis (session, invitation,
  # défi, jeton d'exécutant) n'est jamais stocké en clair.
  module Secrets
    def self.token(bytes : Int32 = 32) : String
      base64url(Random::Secure.random_bytes(bytes))
    end

    def self.digest(value : String) : String
      OpenSSL::Digest.new("SHA256").update(value).final.hexstring
    end

    def self.base64url(bytes : Bytes) : String
      Base64.urlsafe_encode(bytes, padding: false)
    end

    def self.decode64?(value : String) : Bytes?
      normalized = value.strip.tr("-_", "+/").delete('=')
      return Bytes.empty if normalized.empty?
      normalized += "=" * ((4 - normalized.size % 4) % 4)
      Base64.decode(normalized)
    rescue Base64::Error
      nil
    end

    def self.equal?(a : String, b : String) : Bool
      Crypto::Subtle.constant_time_compare(a, b)
    end

    # Référence lisible d'une double validation (`DV-XXXX-XXXX`).
    def self.reference(prefix : String) : String
      alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
      body = String.build do |io|
        8.times do |index|
          io << '-' if index == 4
          io << alphabet[Random::Secure.rand(alphabet.size)]
        end
      end
      "#{prefix}-#{body}"
    end
  end
end
