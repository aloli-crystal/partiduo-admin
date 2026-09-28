# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Cabinet comptable (ADR-008 D2) : administre des dossiers et leurs
  # gestionnaires. Le parc d'Aloli est lui-même un cabinet.
  class Firm < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :name, :string, max_size: 150, unique: true
    field :siren, :string, max_size: 9, blank: true, default: ""
    field :email, :string, max_size: 254, blank: true, default: ""
    field :active, :bool, default: true
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def to_s(io : IO) : Nil
      io << name
    end
  end

  # Utilisateur de l'administration : super-admin, admin de cabinet ou
  # gestionnaire de dossiers (ADR-008 D2). Distinct des utilisateurs des
  # dossiers, qui n'existent que dans leur instance (ADR-008 D3).
  class User < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :email, :email, unique: true
    field :first_name, :string, max_size: 100, blank: true, default: ""
    field :last_name, :string, max_size: 100, blank: true, default: ""
    field :locale, :string, max_size: 8, default: "fr"
    field :role, :string, max_size: 16
    field :firm, :many_to_one, to: PartiduoAdmin::Firm, null: true, blank: true, on_delete: :protect
    field :password_digest, :string, max_size: 128, null: true, blank: true
    field :password_changed_at, :date_time, null: true, blank: true
    field :totp_secret, :string, max_size: 64, null: true, blank: true
    field :totp_pending_secret, :string, max_size: 64, null: true, blank: true
    field :totp_enabled_at, :date_time, null: true, blank: true
    field :last_otp_counter, :big_int, null: true, blank: true
    field :failed_attempts, :int, default: 0
    field :last_failed_at, :date_time, null: true, blank: true
    field :locked_at, :date_time, null: true, blank: true
    field :active, :bool, default: true
    field :last_login_at, :date_time, null: true, blank: true
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def super_admin? : Bool
      role == Config::SUPER_ADMIN
    end

    def firm_admin? : Bool
      role == Config::FIRM_ADMIN
    end

    def file_manager? : Bool
      role == Config::FILE_MANAGER
    end

    def totp_enabled? : Bool
      !totp_secret.nil? && !totp_enabled_at.nil?
    end

    def usable_password? : Bool
      !password_digest.nil?
    end

    def locked? : Bool
      !locked_at.nil?
    end

    def can_sign_in? : Bool
      active == true && (super_admin? || firm.try(&.active) == true)
    end

    def display_name : String
      name = "#{first_name} #{last_name}".strip
      name.empty? ? email.to_s : name
    end

    def role_key : String
      "admin.roles.#{role}"
    end

    def firm_name : String
      firm.try(&.name) || ""
    end
  end

  # Donneur d'ordre (ADR-008 D2, question ouverte 1) : celui qui commande et
  # paie un dossier — un cabinet, la société elle-même ou un autre payeur.
  # Base de la facturation future (tarifs, périodes et factures hors
  # périmètre). `firm` : le cabinet dont le donneur d'ordre relève (portée des
  # droits) ; pour `kind = firm`, c'est le cabinet payeur lui-même.
  class Payer < Marten::Model
    KINDS = %w[firm company other]

    field :id, :big_int, primary_key: true, auto: true
    field :kind, :string, max_size: 16
    field :firm, :many_to_one, to: PartiduoAdmin::Firm, on_delete: :protect
    field :name, :string, max_size: 150
    field :siren, :string, max_size: 9, blank: true, default: ""
    field :vat_number, :string, max_size: 20, blank: true, default: ""
    field :street, :string, max_size: 200, blank: true, default: ""
    field :postcode, :string, max_size: 16, blank: true, default: ""
    field :city, :string, max_size: 100, blank: true, default: ""
    field :country, :string, max_size: 2, default: "FR"
    field :contact_name, :string, max_size: 150, blank: true, default: ""
    field :contact_email, :string, max_size: 254, blank: true, default: ""
    field :contact_phone, :string, max_size: 32, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def kind_key : String
      "admin.payers.kinds.#{kind}"
    end

    def billing_address : String
      [street.to_s, "#{postcode} #{city}".strip, country.to_s].reject(&.empty?).join(", ")
    end

    def firm_name : String
      firm.try(&.name) || ""
    end
  end
end
