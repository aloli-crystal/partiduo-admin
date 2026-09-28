# SPDX-License-Identifier: AGPL-3.0-or-later

require "password-policy"

module PartiduoAdmin
  # Paramètres de l'administration, lus dans l'environnement.
  module Config
    ISSUER = "Partiduo administration"

    # Rôles (ADR-008 D2).
    SUPER_ADMIN  = "super_admin"
    FIRM_ADMIN   = "firm_admin"
    FILE_MANAGER = "file_manager"
    ROLES        = [SUPER_ADMIN, FIRM_ADMIN, FILE_MANAGER]

    LOCALES = %w[fr en nl]

    # Limitation des tentatives (ADR-002, CNIL 2022-100) : mêmes paliers que
    # les dossiers.
    THROTTLE_AFTER    =  3
    LOCK_AFTER        = 10
    THROTTLE_BASE     = 5.seconds
    THROTTLE_MAXIMUM  = 15.minutes
    PENDING_LIFETIME  = 5.minutes
    CHALLENGE_TIMEOUT = 5.minutes
    IDLE_TIMEOUT      = 30.minutes
    SESSION_LIFETIME  = 8.hours
    INVITATION_TTL    = 7.days
    RECOVERY_CODES    = 10

    # Conservation des archives : dix ans (Code de commerce, art. L123-22).
    ARCHIVE_RETENTION_YEARS = Protocol::ARCHIVE_RETENTION_YEARS

    # Double validation : une demande non validée expire.
    APPROVAL_TTL = 7.days

    # Quota Let's Encrypt : 50 certificats par semaine pour le domaine
    # enregistré (ADR-001 D2). Alerte à partir de `LE_WARNING`.
    LE_WEEKLY_LIMIT = 50
    LE_WARNING      = 40

    # Seuils de supervision (ADR-008 D5).
    CERT_WARNING_DAYS   =   21
    DISK_WARNING_RATIO  = 0.10
    BACKUP_WARNING_AGE  = 36.hours
    AGENT_SILENCE_ALERT = 30.minutes

    def self.password_policy : PasswordPolicy::Policy
      PasswordPolicy::Policy.long(use_case: PasswordPolicy::UseCase::WithAccessRestriction)
    end

    def self.bcrypt_cost : Int32
      if value = ENV["PARTIDUO_BCRYPT_COST"]?.try(&.to_i?)
        return value.clamp(4, 31)
      end
      ENV["MARTEN_ENV"]? == "test" ? 4 : 12
    end

    # Domaine du parc (ADR-001 D2) : `partiduo.app` en production,
    # `partiduo.localhost` en développement.
    def self.domain : String
      ENV["PARTIDUO_DOMAIN"]?.presence || "partiduo.localhost"
    end

    # Nom d'hôte de l'administration (ADR-008 D1 : `admin.<domaine>`).
    def self.host : String
      ENV["PARTIDUO_ADMIN_HOST"]?.presence || "admin.#{domain}"
    end

    # Adresse publique de l'administration, pour les liens des courriels.
    def self.base_url : String
      ENV["PARTIDUO_ADMIN_URL"]?.presence || (domain.ends_with?(".localhost") ? "http://#{host}:8200" : "https://#{host}")
    end

    def self.database_url : String
      ENV["DATABASE_URL"]?.presence ||
        (ENV["MARTEN_ENV"]? == "test" ? "postgres:///partiduo_admin_test?host=/tmp" : "postgres:///partiduo_admin?host=/tmp")
    end

    # Partie de confiance WebAuthn : le nom d'hôte de l'administration ; les
    # passkeys des dossiers ne s'y présentent donc pas (autre RP ID).
    def self.rp_id : String
      ENV["PARTIDUO_ADMIN_RP_ID"]?.presence || host
    end

    def self.origin_allowed?(origin : String) : Bool
      if list = ENV["PARTIDUO_ADMIN_WEBAUTHN_ORIGINS"]?.presence
        return list.split(',').map(&.strip).includes?(origin)
      end
      uri = URI.parse(origin)
      host = uri.host.to_s.downcase
      return false if host.empty? || !uri.path.empty? || uri.query || uri.user
      return false unless host == rp_id.downcase
      case uri.scheme
      when "https" then true
      when "http"  then host == "localhost" || host.ends_with?(".localhost")
      else              false
      end
    rescue URI::Error
      false
    end

    # Adresse d'expédition des courriels (invitations, alertes).
    def self.mail_from : String
      ENV["PARTIDUO_ADMIN_MAIL_FROM"]?.presence || "no-reply@#{domain}"
    end

    # Destinataires des alertes par courriel (liste séparée par des virgules).
    def self.alert_recipients : Array(String)
      (ENV["PARTIDUO_ADMIN_ALERTS_TO"]? || "").split(',').map(&.strip).reject(&.empty?)
    end

    # Horloge remplaçable dans les specs.
    class_property clock : Proc(Time) = -> { Time.utc }

    def self.now : Time
      clock.call
    end
  end
end

module PartiduoAdmin
  # Identifiant d'une clé étrangère Marten (dont le type est l'union des
  # valeurs de champ) ramené à `Int64?`.
  def self.id?(value) : Int64?
    case value
    when Int64 then value
    when Int32 then value.to_i64
    end
  end
end
