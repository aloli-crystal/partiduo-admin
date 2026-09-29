# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Structures (ADR-008 D2, D-VAL2-002) : cabinets, gestionnaires
  # indépendants, parc sans cabinet ; mode des opérations sensibles de
  # chacune.
  class FirmsHandler < ScreenHandler
    def get
      require_fleet!
      page("admin/firms.html", {"firms" => firms, "kinds" => kinds("cabinet"), "fleet_exists" => fleet_exists?})
    end

    def post
      require_fleet!
      kind = field("kind").presence || "cabinet"
      outcome = Directory.create_firm(user, field("name"), field("siren").gsub(/\s/, ""), field("email"), kind)
      if outcome.ok?
        flash["success"] = I18n.t("admin.saved")
        return redirect("/firms")
      end
      page("admin/firms.html", {"firms" => firms, "errors" => translate(outcome.errors), "kinds" => kinds(kind),
                                "fleet_exists" => fleet_exists?, "name" => field("name"), "siren" => field("siren"),
                                "email" => field("email")}, status: 422)
    end

    private def firms
      Firm.all.order("name").to_a.map do |firm|
        {"firm" => firm, "mode_key" => "admin.dual_approval.modes.#{ApprovalMode.mode(firm)}",
         "team" => ApprovalMode.team_size(firm)}
      end
    end

    private def kinds(selected : String)
      Firm::KINDS.map { |code| {"value" => code, "key" => "admin.firms.kinds.#{code}", "selected" => code == selected} }
    end

    private def fleet_exists? : Bool
      Firm.filter(kind: "fleet").exists?
    end
  end

  class UsersHandler < ScreenHandler
    def get
      require_admin!
      users = Access.users(user).order("email").to_a
      rows = users.map { |target| {"user" => target, "manage" => Access.can_manage_user?(user, target) && target.pk != user.pk} }
      page("admin/users.html", {"rows" => rows})
    end
  end

  # Invitation d'un utilisateur d'administration.
  class UserNewHandler < ScreenHandler
    def get
      require_admin!
      form(Directory::UserInput.new(email: "", firm_id: PartiduoAdmin.id?(user.firm_id)), Fleet::Errors.new)
    end

    def post
      require_admin!
      input = Directory::UserInput.new(email: field("email"), first_name: field("first_name"), last_name: field("last_name"),
        role: field("role"), firm_id: field("firm_id").to_i64?, locale: field("locale").presence || "fr")
      outcome = Directory.invite_user(user, input)
      if outcome.ok?
        flash["success"] = I18n.t("admin.users.invited", email: outcome.value!.email.to_s)
        return redirect("/users")
      end
      form(input, outcome.errors, 422)
    end

    private def form(input : Directory::UserInput, errors : Fleet::Errors, status = 200)
      t = translate(errors)
      opt = ->(value : String, label : String, current : String) { FormField::Option.new(value, label, value == current) }
      fields = [
        FormField.new("email", I18n.t("admin.users.fields.email"), input.email, "email", errors: errs(t, "email"), required: true),
        FormField.new("first_name", I18n.t("admin.users.fields.first_name"), input.first_name),
        FormField.new("last_name", I18n.t("admin.users.fields.last_name"), input.last_name),
        FormField.new("role", I18n.t("admin.users.fields.role"), input.role, "select",
          Access.assignable_roles(user).map { |role| opt.call(role, I18n.t("admin.roles.#{role}"), input.role) },
          errs(t, "role"), required: true, help: I18n.t("admin.users.help.role")),
      ]
      if user.super_admin?
        fields << FormField.new("firm_id", I18n.t("admin.users.fields.firm"), input.firm_id.to_s, "select",
          [opt.call("", "—", "")] + Firm.all.order("name").map { |firm| opt.call(firm.pk.to_s, firm.name.to_s, input.firm_id.to_s) },
          errs(t, "firm_id"), help: I18n.t("admin.users.help.firm"))
      end
      fields << FormField.new("locale", I18n.t("admin.users.fields.locale"), input.locale, "select",
        Config::LOCALES.map { |code| opt.call(code, I18n.t("admin.languages.#{code}"), input.locale) })
      page("admin/user_new.html", {"fields" => fields, "base_errors" => errs(t, "base")}, status: status)
    end
  end

  class UserCommandHandler < ScreenHandler
    def post
      require_admin!
      target = Access.users(user).filter(id: id_param).first
      raise Access::Denied.new("user") if target.nil?
      done = case params["command"].to_s
             when "reinvite" then Directory.reinvite(user, target)
             when "disable"  then Directory.set_active(user, target, false)
             when "enable"   then Directory.set_active(user, target, true)
             when "unlock"   then Directory.unlock(user, target)
             else                 false
             end
      raise Access::Denied.new("user") unless done
      flash["success"] = I18n.t("admin.saved")
      go("/users")
    end
  end

  class PayersHandler < ScreenHandler
    def get
      page("admin/payers.html", {"payers" => Access.payers(user).order("name").to_a, "can_edit" => !user.file_manager?})
    end
  end

  class PayerFormHandler < ScreenHandler
    def get
      require_admin!
      payer = existing
      input = if payer
                Directory::PayerInput.new(kind: payer.kind.to_s, firm_id: PartiduoAdmin.id?(payer.firm_id), name: payer.name.to_s,
                  siren: payer.siren.to_s, vat_number: payer.vat_number.to_s, street: payer.street.to_s,
                  postcode: payer.postcode.to_s, city: payer.city.to_s, country: payer.country.to_s,
                  contact_name: payer.contact_name.to_s, contact_email: payer.contact_email.to_s,
                  contact_phone: payer.contact_phone.to_s)
              else
                Directory::PayerInput.new(kind: "company", firm_id: PartiduoAdmin.id?(user.firm_id), name: "")
              end
      form(payer, input, Fleet::Errors.new)
    end

    def post
      require_admin!
      payer = existing
      input = Directory::PayerInput.new(kind: field("kind"), firm_id: field("firm_id").to_i64?, name: field("name"),
        siren: field("siren").gsub(/\s/, ""), vat_number: field("vat_number"), street: field("street"),
        postcode: field("postcode"), city: field("city"), country: field("country").upcase.presence || "FR",
        contact_name: field("contact_name"), contact_email: field("contact_email"), contact_phone: field("contact_phone"))
      outcome = Directory.save_payer(user, input, payer)
      if outcome.ok?
        flash["success"] = I18n.t("admin.saved")
        return redirect("/payers")
      end
      form(payer, input, outcome.errors, 422)
    end

    private def existing : Payer?
      return unless params.has_key?("id")
      payer = Access.payers(user).filter(id: id_param).first
      raise Access::Denied.new("payer") if payer.nil? || !Access.can_manage_payer?(user, payer.firm_id)
      payer
    end

    private def form(payer : Payer?, input : Directory::PayerInput, errors : Fleet::Errors, status = 200)
      t = translate(errors)
      opt = ->(value : String, label : String, current : String) { FormField::Option.new(value, label, value == current) }
      e = ->(name : String) { t[name]? || [] of String }
      fields = [
        FormField.new("kind", I18n.t("admin.payers.fields.kind"), input.kind, "select",
          Payer::KINDS.map { |kind| opt.call(kind, I18n.t("admin.payers.kinds.#{kind}"), input.kind) }, e.call("kind"), required: true,
          help: I18n.t("admin.payers.help.kind")),
      ]
      if user.super_admin?
        fields << FormField.new("firm_id", I18n.t("admin.payers.fields.firm"), input.firm_id.to_s, "select",
          Firm.all.order("name").map { |firm| opt.call(firm.pk.to_s, firm.name.to_s, input.firm_id.to_s) }, e.call("firm_id"), required: true)
      end
      fields += [
        FormField.new("name", I18n.t("admin.payers.fields.name"), input.name, errors: e.call("name"), required: true),
        FormField.new("siren", I18n.t("admin.payers.fields.siren"), input.siren, errors: e.call("siren")),
        FormField.new("vat_number", I18n.t("admin.payers.fields.vat_number"), input.vat_number),
        FormField.new("street", I18n.t("admin.payers.fields.street"), input.street, errors: e.call("street"), required: true),
        FormField.new("postcode", I18n.t("admin.payers.fields.postcode"), input.postcode),
        FormField.new("city", I18n.t("admin.payers.fields.city"), input.city, errors: e.call("city"), required: true),
        FormField.new("country", I18n.t("admin.payers.fields.country"), input.country, errors: e.call("country"),
          help: I18n.t("admin.payers.help.country")),
        FormField.new("contact_name", I18n.t("admin.payers.fields.contact_name"), input.contact_name),
        FormField.new("contact_email", I18n.t("admin.payers.fields.contact_email"), input.contact_email, "email", errors: e.call("contact_email")),
        FormField.new("contact_phone", I18n.t("admin.payers.fields.contact_phone"), input.contact_phone, "tel"),
      ]
      page("admin/payer_form.html", {"payer" => payer, "fields" => fields, "base_errors" => e.call("base"),
                                     "action" => payer ? "/payers/#{payer.pk}/edit" : "/payers/new"}, status: status)
    end
  end

  # Dossiers par donneur d'ordre, exportables en CSV (`?format=csv`) : base
  # de la facturation future (ADR-008, question ouverte 1).
  class PayerDossiersHandler < ScreenHandler
    def get
      if query("format") == "csv"
        Audit.log(user, "payers.export", ip: ip)
        response = respond(Directory.csv(user), content_type: "text/csv; charset=utf-8")
        response.headers["Content-Disposition"] = %(attachment; filename="dossiers-par-donneur-d-ordre-#{Config.now.to_s("%F")}.csv")
        return response
      end
      groups = Directory.dossiers_by_payer(user).map { |payer, dossiers| {"payer" => payer, "dossiers" => dossiers} }
      page("admin/payer_dossiers.html", {"groups" => groups})
    end
  end
end
