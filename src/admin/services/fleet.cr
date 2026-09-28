# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Actions de la première version (ADR-008 D5) : chaque action vérifie les
  # droits (`Access`) et l'état du dossier, enregistre une tâche, trace dans
  # le journal d'audit. Les erreurs sont des clés i18n par champ.
  module Fleet
    alias Errors = Hash(String, Array(String))

    # Issue d'une action : erreurs par champ (clés i18n) ou objet produit.
    class Outcome(T)
      getter value : T?
      getter errors : Errors

      def initialize(@value : T? = nil, @errors : Errors = Errors.new)
      end

      def ok? : Bool
        errors.empty?
      end

      def value! : T
        @value || raise NilAssertionError.new("action refusée : #{errors}")
      end

      def self.failure(field : String, key : String) : Outcome(T)
        new(nil, {field => [key]})
      end
    end

    record DossierInput,
      slug : String, label : String, regime : String, locale : String = "fr",
      siren : String = "", vat_number : String = "",
      modules : Array(String) = ["accounting", "invoicing"], extensions : Array(String) = [] of String,
      admin_email : String = "", server_id : Int64? = nil, firm_id : Int64? = nil, payer_id : Int64? = nil,
      version : String = "", backup_schedule : String = "daily", backup_retention_days : Int32 = 30

    EMAIL = /\A[^@\s'"]+@[^@\s'"]+\.[^@\s'"]+\z/

    def self.any(value) : JSON::Any
      Tasks.any(value)
    end

    # --- Création -----------------------------------------------------------

    def self.create_dossier(user : User, input : DossierInput, now : Time = Config.now) : Outcome(Dossier)
      slug = input.slug.strip.downcase
      errors = identity_errors(input, slug)
      server, firm, payer = references(user, input, now, errors)
      return Outcome(Dossier).new(nil, errors) unless errors.empty? && server && firm && payer

      version = input.version.presence || Release.filter(is_default: true).first.try(&.version) || ""
      dossier = Dossier.create!(
        slug: slug, label: input.label.strip, regime: input.regime, locale: input.locale,
        siren: input.siren, vat_number: input.vat_number.strip.upcase,
        modules: input.modules.uniq.join(','), extensions: input.extensions.uniq.join(','),
        admin_email: input.admin_email.strip.downcase, server: server, firm: firm, payer: payer,
        version: version, state: "creating", backup_schedule: input.backup_schedule,
        backup_retention_days: input.backup_retention_days,
      )
      params = Tasks.dossier_params(dossier)
      {"name" => dossier.label, "regime" => dossier.regime, "locale" => dossier.locale, "siren" => dossier.siren,
       "vat" => dossier.vat_number, "admin_email" => dossier.admin_email}.each { |key, value| params[key] = any(value.to_s) }
      Tasks.enqueue("instance.create", server, params, user, dossier)
      Audit.log(user, "dossier.create", target: dossier,
        detail: {"modules" => dossier.modules.to_s, "extensions" => dossier.extensions.to_s, "payer" => payer.name.to_s})
      Outcome(Dossier).new(dossier)
    end

    # Accumule une clé d'erreur sur un champ.
    private def self.add(errors : Errors, field : String, key : String) : Nil
      (errors[field] ||= [] of String) << key
    end

    # Contrôles de la saisie elle-même.
    private def self.identity_errors(input : DossierInput, slug : String) : Errors
      errors = Errors.new
      if !Protocol.valid_slug?(slug)
        add(errors, "slug", "admin.errors.dossier.slug")
      elsif Dossier.filter(slug: slug).exists?
        add(errors, "slug", "admin.errors.dossier.slug_taken")
      end
      add(errors, "label", "admin.errors.required") if input.label.strip.empty?
      add(errors, "regime", "admin.errors.dossier.regime") unless %w[fr be].includes?(input.regime)
      add(errors, "locale", "admin.errors.dossier.locale") unless Config::LOCALES.includes?(input.locale)
      add(errors, "siren", "admin.errors.siren") unless input.siren.empty? || Siren.valid?(input.siren)
      add(errors, "modules", "admin.errors.dossier.modules") unless valid_modules?(input.modules)
      add(errors, "extensions", "admin.errors.dossier.extensions") unless valid_extensions?(input.extensions)
      add(errors, "admin_email", "admin.errors.email") unless EMAIL.matches?(input.admin_email.strip)
      schedule_errors(input, errors)
      errors
    end

    private def self.schedule_errors(input : DossierInput, errors : Errors) : Nil
      # Version choisie : une version publiée, jamais une valeur libre (elle
      # nomme le répertoire que l'exécutant met en service).
      unless input.version.empty? || Release.filter(version: input.version).exists?
        add(errors, "version", "admin.errors.invalid")
      end
      add(errors, "backup_schedule", "admin.errors.invalid") unless Dossier::SCHEDULES.includes?(input.backup_schedule)
      add(errors, "backup_retention_days", "admin.errors.dossier.retention") unless (1..3650).includes?(input.backup_retention_days)
    end

    def self.valid_modules?(modules : Array(String)) : Bool
      !modules.empty? && modules.all? { |code| Protocol::MODULES.includes?(code) }
    end

    def self.valid_extensions?(extensions : Array(String)) : Bool
      extensions.all? { |code| Protocol::CODE.matches?(code) }
    end

    # Serveur, cabinet et donneur d'ordre désignés, droits et quota.
    private def self.references(user : User, input : DossierInput, now : Time, errors : Errors) : {Server?, Firm?, Payer?}
      server = input.server_id.try { |id| Server.filter(id: id, active: true).first }
      firm = input.firm_id.try { |id| Firm.filter(id: id, active: true).first }
      payer = input.payer_id.try { |id| Payer.filter(id: id).first }
      add(errors, "server_id", "admin.errors.required") if server.nil?
      add(errors, "firm_id", "admin.errors.required") if firm.nil?
      add(errors, "payer_id", "admin.errors.dossier.payer_required") if payer.nil?
      if firm
        add(errors, "payer_id", "admin.errors.dossier.payer_scope") if payer && payer.firm_id != firm.pk && !user.super_admin?
        add(errors, "firm_id", "admin.errors.forbidden") unless Access.can_create_dossier?(user, firm.pk)
      end
      add(errors, "base", "admin.errors.dossier.quota") if server && LetsEncrypt.quota_reached?(server.domain.to_s, now)
      {server, firm, payer}
    end

    # --- Modules et extensions (ADR-006 D2) --------------------------------

    def self.change_modules(user : User, dossier : Dossier, modules : Array(String), extensions : Array(String)) : Outcome(Task)
      return Outcome(Task).failure("base", "admin.errors.forbidden") unless Access.can?(user, :modules, dossier)
      return Outcome(Task).failure("base", "admin.errors.dossier.not_active") unless dossier.state == "active"
      return Outcome(Task).failure("modules", "admin.errors.dossier.modules") unless valid_modules?(modules)
      return Outcome(Task).failure("extensions", "admin.errors.dossier.extensions") unless valid_extensions?(extensions)
      # Extensions retirées avant les modules (une extension requiert un
      # module, jamais l'inverse), modules ajoutés avant les extensions ;
      # l'exécutant affine l'ordre selon les dépendances que rend l'instance
      # (D-AFN-006). Les données d'une pièce désactivée sont conservées.
      disable = (dossier.extension_list - extensions) + (dossier.module_list - modules)
      enable = (modules - dossier.module_list) + (extensions - dossier.extension_list)
      return Outcome(Task).failure("base", "admin.errors.dossier.no_change") if enable.empty? && disable.empty?
      params = Tasks.dossier_params(dossier)
      params["enable"] = any(enable)
      params["disable"] = any(disable)
      params["target_modules"] = any(modules)
      params["target_extensions"] = any(extensions)
      task = Tasks.enqueue("instance.modules", dossier.server!, params, user, dossier)
      Audit.log(user, "dossier.modules", target: dossier, detail: {"enable" => enable.join(','), "disable" => disable.join(',')})
      Outcome(Task).new(task)
    end

    # --- Cycle de vie -------------------------------------------------------

    TRANSITIONS = {
      "suspend"         => {"instance.suspend", "active"},
      "resume"          => {"instance.resume", "suspended"},
      "archive"         => {"instance.archive", "active|suspended"},
      "restore_archive" => {"instance.restore_archive", "archived"},
    }

    def self.lifecycle(user : User, dossier : Dossier, action : String, reason : String = "") : Outcome(Task)
      kind, from = TRANSITIONS[action]? || return Outcome(Task).failure("base", "admin.errors.invalid")
      return Outcome(Task).failure("base", "admin.errors.forbidden") unless Access.can?(user, action_symbol(action), dossier)
      return Outcome(Task).failure("base", "admin.errors.dossier.state") unless from.split('|').includes?(dossier.state)
      params = Tasks.dossier_params(dossier)
      params["reason"] = any(reason.presence || action)
      task = Tasks.enqueue(kind, dossier.server!, params, user, dossier)
      Audit.log(user, "dossier.#{action}", target: dossier, detail: {"reason" => reason})
      Outcome(Task).new(task)
    end

    private def self.action_symbol(action : String) : Symbol
      case action
      when "suspend"         then :suspend
      when "resume"          then :resume
      when "archive"         then :archive
      when "restore_archive" then :restore_archive
      else                        :none
      end
    end

    # --- Sauvegardes (ADR-008 D5) -------------------------------------------

    def self.backup_now(user : User?, dossier : Dossier, kind : String = "manual") : Outcome(Task)
      if user && !Access.can?(user, :backup, dossier)
        return Outcome(Task).failure("base", "admin.errors.forbidden")
      end
      return Outcome(Task).failure("base", "admin.errors.dossier.state") unless %w[active suspended].includes?(dossier.state)
      params = Tasks.dossier_params(dossier)
      params["kind"] = any(kind)
      task = Tasks.enqueue("backup.run", dossier.server!, params, user, dossier)
      Audit.log(user, "backup.request", target: dossier, detail: {"kind" => kind}, actor_label: user ? nil : "system")
      Outcome(Task).new(task)
    end

    def self.test_restore(user : User?, backup : Backup) : Outcome(Task)
      dossier = backup.dossier!
      if user && !Access.can?(user, :test_restore, dossier)
        return Outcome(Task).failure("base", "admin.errors.forbidden")
      end
      return Outcome(Task).failure("base", "admin.errors.backup.unusable") unless %w[done verified].includes?(backup.state)
      params = Tasks.dossier_params(dossier)
      params["backup_id"] = any(backup.pk!.as(Int64))
      params["path"] = any(backup.path)
      params["media_path"] = any(backup.media_path)
      params["sha256"] = any(backup.sha256)
      task = Tasks.enqueue("backup.test_restore", dossier.server!, params, user, dossier)
      Audit.log(user, "backup.test_restore", target: dossier, detail: {"backup" => backup.pk.to_s}, actor_label: user ? nil : "system")
      Outcome(Task).new(task)
    end

    # Restauration à une date : la dernière sauvegarde prise à cette date ou
    # avant, dans une instance neuve (`new`, sous-domaine `new_slug`) ou en
    # remplacement (`replace`, après une sauvegarde de sûreté).
    def self.restore(user : User, dossier : Dossier, date : Time, target : String, new_slug : String = "") : Outcome(Task)
      return Outcome(Task).failure("base", "admin.errors.forbidden") unless Access.can?(user, :restore, dossier)
      return Outcome(Task).failure("target", "admin.errors.invalid") unless %w[new replace].includes?(target)
      return Outcome(Task).failure("base", "admin.errors.dossier.state") unless %w[active suspended].includes?(dossier.state)
      backup = Backup.filter(dossier_id: dossier.pk, state__in: %w[done verified], taken_at__lte: date.at_end_of_day)
        .order("-taken_at").first
      return Outcome(Task).failure("date", "admin.errors.backup.none_before") if backup.nil?
      params = Tasks.dossier_params(dossier)
      params["backup_id"] = any(backup.pk!.as(Int64))
      params["path"] = any(backup.path)
      params["media_path"] = any(backup.media_path)
      params["sha256"] = any(backup.sha256)
      params["target"] = any(target)
      if target == "new"
        slug = new_slug.strip.downcase
        return Outcome(Task).failure("new_slug", "admin.errors.dossier.slug") unless Protocol.valid_slug?(slug)
        return Outcome(Task).failure("new_slug", "admin.errors.dossier.slug_taken") if Dossier.filter(slug: slug).exists?
        # Instance neuve : un certificat de plus, compté comme à la création.
        if LetsEncrypt.quota_reached?(dossier.server!.domain.to_s, Config.now)
          return Outcome(Task).failure("base", "admin.errors.dossier.quota")
        end
        copy = Dossier.create!(slug: slug, label: dossier.label, regime: dossier.regime, locale: dossier.locale,
          siren: dossier.siren, vat_number: dossier.vat_number, modules: dossier.modules, extensions: dossier.extensions,
          admin_email: dossier.admin_email, server: dossier.server!, firm: dossier.firm!, payer: dossier.payer!,
          version: backup.version.presence || dossier.version, state: "creating")
        params["new_slug"] = any(slug)
        params["new_host"] = any(copy.host)
      end
      task = Tasks.enqueue("backup.restore", dossier.server!, params, user, dossier)
      Audit.log(user, "backup.restore", target: dossier,
        detail: {"backup" => backup.pk.to_s, "target" => target, "new_slug" => new_slug, "date" => date.to_s("%F")})
      Outcome(Task).new(task)
    end

    # --- Montée de version (ADR-008 D5) -------------------------------------

    def self.upgrade(user : User?, dossier : Dossier, release : Release, wave : Wave? = nil, rank : Int32? = nil) : Outcome(Task)
      if user && wave.nil? && !Access.can?(user, :upgrade, dossier)
        return Outcome(Task).failure("base", "admin.errors.forbidden")
      end
      return Outcome(Task).failure("base", "admin.errors.dossier.not_active") unless dossier.state == "active"
      return Outcome(Task).failure("release_id", "admin.errors.release.same") if dossier.version == release.version
      params = Tasks.dossier_params(dossier)
      params["from_version"] = any(dossier.version)
      params["version"] = any(release.version)
      task = Tasks.enqueue("instance.upgrade", dossier.server!, params, user, dossier, wave: wave, wave_rank: rank)
      Audit.log(user, "dossier.upgrade", target: dossier, detail: {"from" => dossier.version.to_s, "to" => release.version.to_s})
      Outcome(Task).new(task)
    end
  end

  # SIREN : neuf chiffres, clé de Luhn.
  module Siren
    def self.valid?(value : String) : Bool
      return false unless value.matches?(/\A\d{9}\z/)
      sum = value.chars.reverse!.each_with_index.sum do |char, index|
        digit = char.to_i
        digit *= 2 if index.odd?
        digit > 9 ? digit - 9 : digit
      end
      sum % 10 == 0
    end
  end
end
