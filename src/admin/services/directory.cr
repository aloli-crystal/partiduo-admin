# SPDX-License-Identifier: AGPL-3.0-or-later

require "csv"

module PartiduoAdmin
  # Référentiels de l'administration : cabinets, utilisateurs et
  # affectations, donneurs d'ordre, serveurs, versions.
  module Directory
    alias Outcome = Fleet::Outcome
    alias Errors = Fleet::Errors

    record UserInput, email : String, first_name : String = "", last_name : String = "",
      role : String = Config::FILE_MANAGER, firm_id : Int64? = nil, locale : String = "fr"

    # Crée un utilisateur sans secret et lui envoie une invitation : il
    # choisit lui-même ses moyens d'authentification (ADR-002).
    def self.invite_user(actor : User?, input : UserInput, now : Time = Config.now) : Outcome(User)
      email = input.email.strip.downcase
      firm_id = input.role == Config::SUPER_ADMIN ? nil : input.firm_id
      firm_id = PartiduoAdmin.id?(actor.firm_id) if actor && actor.firm_admin?
      errors = user_errors(actor, input, email, firm_id)
      return Outcome(User).new(nil, errors) unless errors.empty?
      locale = Config::LOCALES.includes?(input.locale) ? input.locale : "fr"
      user = User.create!(email: email, first_name: input.first_name.strip, last_name: input.last_name.strip,
        role: input.role, firm_id: firm_id, locale: locale)
      raw = Auth::Invitations.issue(user, actor, now)
      Mailer.invitation(user, Auth::Invitations.url(raw))
      Audit.log(actor, "user.invite", target: user, detail: {"role" => user.role.to_s}, actor_label: actor ? nil : "bootstrap")
      Outcome(User).new(user)
    end

    private def self.add(errors : Errors, field : String, key : String) : Nil
      (errors[field] ||= [] of String) << key
    end

    private def self.user_errors(actor : User?, input : UserInput, email : String, firm_id : Int64?) : Errors
      errors = Errors.new
      add(errors, "email", "admin.errors.email") unless Fleet::EMAIL.matches?(email)
      add(errors, "email", "admin.errors.user.email_taken") if User.filter(email: email).exists?
      allowed = actor.nil? ? Config::ROLES : Access.assignable_roles(actor)
      add(errors, "role", "admin.errors.forbidden") unless allowed.includes?(input.role)
      if input.role != Config::SUPER_ADMIN && (firm_id.nil? || !Firm.filter(id: firm_id).exists?)
        add(errors, "firm_id", "admin.errors.required")
      end
      independent_errors(input, firm_id, errors) unless input.role == Config::SUPER_ADMIN
      errors
    end

    # Gestionnaire indépendant : une seule personne, qui gère tous ses
    # dossiers (rôle d'admin de sa structure). Une équipe, c'est un cabinet
    # (D-VAL2-002).
    private def self.independent_errors(input : UserInput, firm_id : Int64?, errors : Errors) : Nil
      firm = firm_id.try { |id| Firm.filter(id: id).first }
      return unless firm && firm.independent?
      add(errors, "role", "admin.errors.firm.independent_role") unless input.role == Config::FIRM_ADMIN
      add(errors, "firm_id", "admin.errors.firm.independent_single") if User.filter(firm_id: firm.pk, active: true).exists?
    end

    # Recours pour un utilisateur de l'administration qui a perdu ses
    # moyens : nouvelle invitation, sessions et secrets révoqués.
    def self.reinvite(actor : User, user : User, now : Time = Config.now) : Bool
      return false unless Access.can_manage_user?(actor, user) && actor.pk != user.pk
      Auth::Sessions.revoke_all(user, now)
      user.password_digest = nil
      user.totp_secret = nil
      user.totp_enabled_at = nil
      user.last_otp_counter = nil
      user.save!
      Passkey.filter(user_id: user.pk).delete
      RecoveryCode.filter(user_id: user.pk).delete
      Auth::Throttle.unlock(user)
      raw = Auth::Invitations.issue(user, actor, now)
      Mailer.invitation(user, Auth::Invitations.url(raw))
      Audit.log(actor, "user.reinvite", target: user)
      true
    end

    def self.set_active(actor : User, user : User, active : Bool) : Bool
      return false unless Access.can_manage_user?(actor, user) && actor.pk != user.pk
      user.active = active
      user.save!
      Auth::Sessions.revoke_all(user) unless active
      Audit.log(actor, active ? "user.enable" : "user.disable", target: user)
      # Équipe réduite : la validation à deux se désactive d'elle-même s'il
      # ne reste qu'une personne habilitée (D-VAL2-003).
      ApprovalMode.after_team_change(user) unless active
      true
    end

    def self.unlock(actor : User, user : User) : Bool
      return false unless Access.can_manage_user?(actor, user)
      Auth::Throttle.unlock(user)
      Audit.log(actor, "user.unlock", target: user)
      true
    end

    # Affectation d'un dossier à un gestionnaire (ADR-008 D2).
    def self.assign(actor : User, manager : User, dossier : Dossier) : Bool
      return false unless manager.file_manager? && Access.can_manage_user?(actor, manager)
      return false unless Access.can?(actor, :approve, dossier) && dossier.firm_id == manager.firm_id
      return true if Assignment.filter(user_id: manager.pk, dossier_id: dossier.pk).exists?
      Assignment.create!(user: manager, dossier: dossier)
      Audit.log(actor, "assignment.add", target: dossier, detail: {"manager" => manager.email.to_s})
      true
    end

    def self.unassign(actor : User, manager : User, dossier : Dossier) : Bool
      return false unless Access.can_manage_user?(actor, manager)
      Assignment.filter(user_id: manager.pk, dossier_id: dossier.pk).delete
      Audit.log(actor, "assignment.remove", target: dossier, detail: {"manager" => manager.email.to_s})
      true
    end

    # --- Cabinets ------------------------------------------------------------

    # Structure : cabinet, gestionnaire indépendant ou parc sans cabinet
    # (un seul). Validation à deux désactivée à la création : l'équipe est
    # vide (D-VAL2-001).
    def self.create_firm(actor : User, name : String, siren : String = "", email : String = "",
                         kind : String = "cabinet") : Outcome(Firm)
      return Outcome(Firm).failure("base", "admin.errors.forbidden") unless Access.fleet?(actor)
      return Outcome(Firm).failure("name", "admin.errors.required") if name.strip.empty?
      return Outcome(Firm).failure("name", "admin.errors.firm.taken") if Firm.filter(name: name.strip).exists?
      return Outcome(Firm).failure("siren", "admin.errors.siren") unless siren.empty? || Siren.valid?(siren)
      return Outcome(Firm).failure("kind", "admin.errors.invalid") unless Firm::KINDS.includes?(kind)
      return Outcome(Firm).failure("kind", "admin.errors.firm.fleet_taken") if kind == "fleet" && Firm.filter(kind: "fleet").exists?
      firm = Firm.create!(name: name.strip, siren: siren, email: email.strip, kind: kind, dual_approval: false)
      Audit.log(actor, "firm.create", target: firm, detail: {"kind" => kind})
      Outcome(Firm).new(firm)
    end

    # --- Donneurs d'ordre ------------------------------------------------------

    record PayerInput, kind : String, firm_id : Int64?, name : String, siren : String = "", vat_number : String = "",
      street : String = "", postcode : String = "", city : String = "", country : String = "FR",
      contact_name : String = "", contact_email : String = "", contact_phone : String = ""

    def self.save_payer(actor : User, input : PayerInput, payer : Payer? = nil) : Outcome(Payer)
      firm_id = actor.firm_admin? ? PartiduoAdmin.id?(actor.firm_id) : input.firm_id
      errors = payer_errors(actor, input, payer, firm_id)
      return Outcome(Payer).new(nil, errors) unless errors.empty?
      record = payer || Payer.new
      record.kind = input.kind
      record.firm_id = firm_id
      record.name = input.name.strip
      record.siren = input.siren
      record.vat_number = input.vat_number.strip.upcase
      record.street = input.street.strip
      record.postcode = input.postcode.strip
      record.city = input.city.strip
      record.country = input.country
      record.contact_name = input.contact_name.strip
      record.contact_email = input.contact_email.strip.downcase
      record.contact_phone = input.contact_phone.strip
      record.save!
      Audit.log(actor, payer ? "payer.update" : "payer.create", target: record)
      Outcome(Payer).new(record)
    end

    private def self.payer_errors(actor : User, input : PayerInput, payer : Payer?, firm_id : Int64?) : Errors
      errors = Errors.new
      add(errors, "kind", "admin.errors.invalid") unless Payer::KINDS.includes?(input.kind)
      add(errors, "firm_id", "admin.errors.required") if firm_id.nil? || !Firm.filter(id: firm_id).exists?
      add(errors, "firm_id", "admin.errors.forbidden") unless Access.can_manage_payer?(actor, firm_id)
      add(errors, "base", "admin.errors.forbidden") if payer && !Access.can_manage_payer?(actor, payer.firm_id)
      add(errors, "name", "admin.errors.required") if input.name.strip.empty?
      add(errors, "street", "admin.errors.required") if input.street.strip.empty?
      add(errors, "city", "admin.errors.required") if input.city.strip.empty?
      contact_errors(input, errors)
      errors
    end

    private def self.contact_errors(input : PayerInput, errors : Errors) : Nil
      add(errors, "siren", "admin.errors.siren") unless input.siren.empty? || Siren.valid?(input.siren)
      add(errors, "country", "admin.errors.invalid") unless input.country.matches?(/\A[A-Z]{2}\z/)
      add(errors, "contact_email", "admin.errors.email") unless input.contact_email.empty? || Fleet::EMAIL.matches?(input.contact_email)
    end

    # Vue « dossiers par donneur d'ordre » (base de la facturation future),
    # exportable en CSV.
    CSV_HEADERS = %w[payer_id payer_kind payer_name payer_siren payer_vat billing_street billing_postcode billing_city
      billing_country contact_name contact_email contact_phone dossier dossier_label regime state modules extensions firm
      created_at archived_at deleted_at]

    def self.dossiers_by_payer(actor : User) : Array({Payer, Array(Dossier)})
      dossiers = Access.dossiers(actor).order("slug").to_a
      grouped = dossiers.group_by(&.payer_id)
      Payer.filter(id__in: grouped.keys.compact).order("name").map { |payer| {payer, grouped[payer.pk]} }
    end

    def self.csv(actor : User) : String
      # Toutes les cellules entre guillemets : un retour chariot dans un nom
      # ne coupe pas la ligne (le constructeur ne cite sinon que le saut de
      # ligne, la virgule et le guillemet).
      CSV.build(quoting: CSV::Builder::Quoting::ALL) do |csv|
        csv.row CSV_HEADERS
        dossiers_by_payer(actor).each do |payer, dossiers|
          dossiers.each do |dossier|
            csv.row [payer.pk.to_s, payer.kind.to_s, payer.name.to_s, payer.siren.to_s, payer.vat_number.to_s,
                     payer.street.to_s, payer.postcode.to_s, payer.city.to_s, payer.country.to_s, payer.contact_name.to_s,
                     payer.contact_email.to_s, payer.contact_phone.to_s, dossier.slug.to_s, dossier.label.to_s,
                     dossier.regime.to_s, dossier.state.to_s, dossier.modules.to_s, dossier.extensions.to_s,
                     dossier.firm_name, dossier.created_at.try(&.to_rfc3339) || "",
                     dossier.archived_at.try(&.to_rfc3339) || "", dossier.deleted_at.try(&.to_rfc3339) || ""].map { |cell| safe(cell) }
          end
        end
      end
    end

    # Caractères de tête à neutraliser (OWASP, « CSV injection ») : formule,
    # tabulation et retour chariot compris.
    FORMULA_LEADS = {'=', '+', '-', '@', '\t', '\r'}

    # Neutralise une cellule qui serait lue comme une formule par un tableur.
    private def self.safe(cell : String) : String
      FORMULA_LEADS.includes?(cell[0]?) ? "'#{cell}" : cell
    end

    # --- Serveurs et versions ------------------------------------------------

    # Crée un serveur ; le jeton de l'exécutant est rendu une seule fois.
    def self.create_server(actor : User, name : String, hostname : String, domain : String) : Outcome({Server, String})
      return Outcome({Server, String}).failure("base", "admin.errors.forbidden") unless Access.fleet?(actor)
      return Outcome({Server, String}).failure("name", "admin.errors.invalid") unless name.matches?(/\A[a-z0-9][a-z0-9-]{0,63}\z/)
      return Outcome({Server, String}).failure("name", "admin.errors.server.taken") if Server.filter(name: name).exists?
      return Outcome({Server, String}).failure("hostname", "admin.errors.required") if hostname.strip.empty?
      unless domain.matches?(/\A[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\z/)
        return Outcome({Server, String}).failure("domain", "admin.errors.invalid")
      end
      token = Secrets.token
      server = Server.create!(name: name, hostname: hostname.strip, domain: domain, token_digest: Secrets.digest(token))
      Audit.log(actor, "server.create", target: server)
      Outcome({Server, String}).new({server, token})
    end

    def self.rotate_token(actor : User, server : Server) : String?
      return unless Access.fleet?(actor)
      token = Secrets.token
      server.token_digest = Secrets.digest(token)
      server.save!
      Audit.log(actor, "server.rotate_token", target: server)
      token
    end

    def self.server_for_token(token : String?) : Server?
      return if token.nil? || token.empty?
      Server.filter(token_digest: Secrets.digest(token), active: true).first
    end

    def self.create_release(actor : User, version : String, notes : String, default : Bool) : Outcome(Release)
      return Outcome(Release).failure("base", "admin.errors.forbidden") unless Access.fleet?(actor)
      return Outcome(Release).failure("version", "admin.errors.invalid") unless Protocol.valid_version?(version)
      return Outcome(Release).failure("version", "admin.errors.release.taken") if Release.filter(version: version).exists?
      Release.filter(is_default: true).update(is_default: false) if default
      release = Release.create!(version: version, notes: notes.strip, is_default: default)
      Audit.log(actor, "release.create", target: release)
      Outcome(Release).new(release)
    end
  end
end
