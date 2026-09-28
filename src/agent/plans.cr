# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAgent
  # Contexte d'exécution d'une tâche : paramètres, système, journal de
  # reprise, résultat renvoyé à l'admin.
  class Context
    getter task : TaskInfo
    getter system : System
    getter journal : Journal
    getter result = {} of String => JSON::Any
    property on_step : Proc(String, Nil) = ->(_step : String) { nil }

    def initialize(@task : TaskInfo, @system : System, @journal : Journal)
    end

    def params : JSON::Any
      task.params
    end

    def param(key : String) : String
      params[key]?.try { |value| value.as_s? || value.raw.to_s } || ""
    end

    def list(key : String) : Array(String)
      params[key]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
    end

    def slug : String
      value = param("slug")
      raise StepError.new("sous-domaine invalide : #{value}", "usage") unless PartiduoAdmin::Protocol.valid_slug?(value)
      value
    end

    def host : String
      param("host")
    end

    # Base du dossier : celle que l'inventaire connaît, sinon celle du mode.
    def database : String
      param("database").presence || @journal["database"]? || system.database_for(slug)
    end

    def log(line : String) : Nil
      system.log(line)
    end

    def set(key : String, value) : Nil
      result[key] = JSON.parse(value.to_json)
    end

    # Étape idempotente : faite une fois, sautée à la reprise.
    def step(name : String, &) : Nil
      if journal.done?(name)
        log("étape « #{name} » déjà faite (reprise)")
        return
      end
      log("— #{name}")
      yield
      journal.mark(name)
      on_step.call(name)
    end

    # Appel de l'interface en ligne de commande d'instance ; échec levé.
    def instance!(action : String, args = [] of String, version : String? = nil, database : String? = nil,
                  slug_override : String? = nil) : JSON::Any
      reply = instance(action, args, version, database, slug_override)
      raise StepError.new("instance #{action} : #{reply.message}", reply.error_code) unless reply.ok?
      reply.data
    end

    def instance(action : String, args = [] of String, version : String? = nil, database : String? = nil,
                 slug_override : String? = nil) : InstanceReply
      full = args + ["--task", task.id.to_s]
      full += ["--requested-by", task.requested_by] unless task.requested_by.empty?
      system.instance(slug_override || slug, action, full, version, database)
    end
  end

  # Liste fermée des types de tâches (ADR-008 D4) et leurs étapes, traduites
  # en appels à partiduo-provision et à `manage instance`. Jamais de
  # commande arbitraire : les paramètres ne sont que des valeurs validées.
  module Plans
    alias Plan = Proc(Context, Nil)

    # Un plan par type de la liste fermée ; tout autre type est refusé.
    PLANS = {
      "instance.create"          => Plan.new { |ctx| create(ctx) },
      "instance.modules"         => Plan.new { |ctx| modules(ctx) },
      "instance.suspend"         => Plan.new { |ctx| suspend(ctx) },
      "instance.resume"          => Plan.new { |ctx| resume(ctx) },
      "instance.archive"         => Plan.new { |ctx| archive(ctx) },
      "instance.restore_archive" => Plan.new { |ctx| restore_archive(ctx) },
      "instance.delete"          => Plan.new { |ctx| delete(ctx) },
      "instance.upgrade"         => Plan.new { |ctx| upgrade(ctx) },
      "instance.admin_invite"    => Plan.new { |ctx| admin_invite(ctx) },
      "backup.run"               => Plan.new { |ctx| backup(ctx, ctx.param("kind").presence || "manual") },
      "backup.prune"             => Plan.new { |ctx| prune(ctx) },
      "backup.test_restore"      => Plan.new { |ctx| test_restore(ctx) },
      "backup.restore"           => Plan.new { |ctx| restore(ctx) },
      "supervision.check"        => Plan.new { |ctx| supervision(ctx) },
    }

    def self.run(ctx : Context) : Nil
      plan = PLANS[ctx.task.kind]? || raise StepError.new("type de tâche refusé : #{ctx.task.kind}", "usage")
      plan.call(ctx)
    end

    # Contrat de l'interface d'instance : majeure attendue (instance-cli.adoc).
    def self.check_contract(ctx : Context, version : String? = nil) : Nil
      ctx.step("contrat") do
        data = ctx.instance!("version", version: version)
        major = data["contract"]?.try(&.as_s?).try(&.split('.').first.to_i?)
        unless major == PartiduoAdmin::Protocol::INSTANCE_CLI_MAJOR
          raise StepError.new("contrat d'instance #{data["contract"]?} non pris en charge", "usage")
        end
      end
    end

    # --- Création -------------------------------------------------------------

    def self.create(ctx : Context) : Nil
      system = ctx.system
      database = system.database_for(ctx.slug)
      ctx.journal["database"] = database
      check_contract(ctx, ctx.param("version").presence)
      ctx.step("provisionnement") do
        exists = system.database_exists?(database)
        provisioned = exists && ctx.instance("status", database: database).data["provisioned"]?.try(&.as_bool?) == true
        if provisioned
          ctx.log("base #{database} déjà provisionnée : rien à refaire")
        else
          output = system.provision(ctx.slug, ctx.params, database, skip_createdb: exists)
          if link = output.match(/https?:\/\/\S+\/invitation\/\S+/)
            ctx.journal["invitation_url"] = link[0]
          end
        end
        system.switch_release(ctx.slug, ctx.param("version")) unless ctx.param("version").empty?
      end
      ctx.step("installation") do
        ctx.journal["certificate"] = system.install_instance(ctx.slug, ctx.host).to_s
      end
      status = ctx.instance!("status", database: database)
      raise StepError.new("instance non provisionnée après création", "refused") unless status["provisioned"]?.try(&.as_bool?)
      ctx.set("database", database)
      ctx.set("version", status["version"]?.try(&.as_s?) || "")
      ctx.set("invitation_url", ctx.journal["invitation_url"]?) if ctx.journal["invitation_url"]?
      ctx.set("certificate", {"issued" => ctx.journal["certificate"]? == "true", "staging" => system.config.acme_staging})
    end

    # --- Modules et extensions (ADR-006 D2 : désactiver conserve les données)

    def self.modules(ctx : Context) : Nil
      check_contract(ctx)
      ctx.list("disable").each do |code|
        ctx.step("désactiver #{code}") { ctx.instance!("disable", [code]) }
      end
      ctx.list("enable").each do |code|
        ctx.step("activer #{code}") { ctx.instance!("enable", [code]) }
      end
      status = ctx.instance!("status")
      ctx.set("modules", status["modules"]? || [] of String)
    end

    # --- Cycle de vie -----------------------------------------------------------

    def self.suspend(ctx : Context) : Nil
      ctx.step("arrêt du service") { ctx.system.service(ctx.slug, "stop") }
      ctx.set("service", ctx.system.service(ctx.slug, "status"))
    end

    def self.resume(ctx : Context) : Nil
      ctx.step("démarrage du service") { ctx.system.service(ctx.slug, "start") }
      ctx.instance!("status")
      ctx.set("service", ctx.system.service(ctx.slug, "status"))
    end

    # Archivage : lecture seule, sauvegarde figée *vérifiée* (relue par
    # pg_restore, empreinte recalculée), instance arrêtée.
    def self.archive(ctx : Context) : Nil
      check_contract(ctx)
      ctx.step("lecture seule") do
        ctx.instance!("read-only", ["on", "--reason", ctx.param("reason").presence || "archivage", "--terminate-sessions"])
      end
      data = backup(ctx, "archive", prefix: "archive")
      ctx.step("vérification de l'archive") do
        path = data["path"].as_s
        raise StepError.new("archive illisible : #{path}") unless ctx.system.pg_restore_list?(path)
        raise StepError.new("empreinte de l'archive altérée") unless ctx.system.sha256(path) == data["sha256"].as_s
        media = data["media_path"].as_s
        raise StepError.new("archive des pièces illisible") unless media.empty? || ctx.system.tar_list?(media)
      end
      ctx.step("arrêt du service") { ctx.system.service(ctx.slug, "stop") }
      verified = data.as_h.merge({"verified" => JSON::Any.new(true)})
      ctx.result.clear
      ctx.set("backup", verified)
    end

    # Restauration d'une archive en instance active : base recréée depuis
    # l'archive si elle a disparu, lecture seule levée, service démarré.
    def self.restore_archive(ctx : Context) : Nil
      ctx.step("base") do
        unless ctx.system.database_exists?(ctx.database)
          path = ctx.param("path")
          raise StepError.new("base absente et aucune archive fournie", "usage") if path.empty?
          ctx.system.createdb(ctx.database)
          ctx.system.pg_restore(ctx.database, ctx.system.guard_backup_path!(path))
        end
      end
      ctx.step("lecture seule levée") { ctx.instance!("read-only", ["off", "--reason", "restauration de l'archive"]) }
      ctx.step("démarrage du service") { ctx.system.service(ctx.slug, "start") }
      ctx.set("version", ctx.instance!("status")["version"]? || "")
    end

    # Suppression définitive (après la durée légale et double validation,
    # vérifiées par l'admin) : service et fichiers retirés, base supprimée,
    # sauvegardes effacées.
    def self.delete(ctx : Context) : Nil
      ctx.log("suppression définitive — validation #{ctx.param("approval_ref")} par #{ctx.list("approvers").join(", ")}")
      ctx.step("retrait du service") { ctx.system.remove_instance(ctx.slug, ctx.host) }
      ctx.step("suppression de la base") { ctx.system.dropdb(ctx.database) }
      ctx.step("suppression des sauvegardes") do
        ctx.list("backups").each { |path| ctx.system.remove(path) }
      end
      ctx.set("deleted", true)
    end

    # --- Montée de version (sauvegarde préalable, retour arrière) --------------

    def self.upgrade(ctx : Context) : Nil
      target = ctx.param("version")
      from = ctx.param("from_version").presence || ctx.system.current_release(ctx.slug) || ""
      raise StepError.new("version cible manquante", "usage") if target.empty?
      check_contract(ctx, target)
      backup_data = backup(ctx, "pre_upgrade", prefix: "pre-upgrade")
      begin
        ctx.step("arrêt du service") { ctx.system.service(ctx.slug, "stop") }
        ctx.step("bascule vers #{target}") { ctx.system.switch_release(ctx.slug, target) }
        ctx.step("migrations") { ctx.instance!("migrate", version: target) }
        ctx.step("démarrage du service") { ctx.system.service(ctx.slug, "start") }
        status = ctx.instance!("status", version: target)
        pending = status["migrations"]?.try(&.["pending"]?).try(&.as_i?) || 0
        raise StepError.new("#{pending} migration(s) en attente après la montée") unless pending.zero?
        ctx.result.clear
        ctx.set("version", status["version"]?.try(&.as_s?) || target)
        ctx.set("backup", backup_data)
        ctx.set("rolled_back", false)
      rescue error : StepError
        ctx.log("échec : #{error.message} — retour arrière vers #{from}")
        rollback(ctx, from, backup_data)
        ctx.result.clear
        ctx.set("backup", backup_data)
        ctx.set("rolled_back", true)
        ctx.set("version", from)
        # Le dossier est revenu à son état d'avant : une reprise repartira
        # de zéro, sauvegarde comprise.
        ctx.journal.reset
        raise StepError.new("montée vers #{target} échouée, retour à #{from} : #{error.message}", error.code)
      end
    end

    def self.rollback(ctx : Context, from : String, backup_data : JSON::Any) : Nil
      system = ctx.system
      system.service(ctx.slug, "stop")
      system.switch_release(ctx.slug, from) unless from.empty?
      if ctx.journal.done?("migrations") || ctx.journal.done?("bascule vers #{ctx.param("version")}")
        # Migrations peut-être en partie appliquées : la base revient à la
        # sauvegarde préalable.
        system.dropdb(ctx.database)
        system.createdb(ctx.database)
        system.pg_restore(ctx.database, backup_data["path"].as_s)
      end
      system.service(ctx.slug, "start")
    end

    # --- Recours d'accès (double validation faite dans l'admin) --------------

    def self.admin_invite(ctx : Context) : Nil
      check_contract(ctx)
      data = ctx.instance!("admin-invite", [ctx.param("email"), "--reason", ctx.param("reason"),
                                            "--approval-ref", ctx.param("approval_ref"),
                                            "--approvers", ctx.list("approvers").join(',')])
      %w[email user_created url expires_at usable_admins].each { |key| ctx.result[key] = data[key] if data[key]? }
    end

    # --- Sauvegardes -------------------------------------------------------------

    # `pg_dump -Fc` et archive des pièces jointes (liste de `backup-plan`),
    # empreinte SHA-256. Noms figés au premier passage : une reprise
    # réutilise les mêmes fichiers.
    def self.backup(ctx : Context, kind : String, prefix : String = "backup") : JSON::Any
      system = ctx.system
      stamp = ctx.journal["#{prefix}.stamp"]? || (ctx.journal["#{prefix}.stamp"] = Time.utc.to_s("%Y%m%dT%H%M%SZ"))
      dir = system.backup_root(ctx.slug)
      dump = File.join(dir, "#{prefix}-#{stamp}.dump")
      list = File.join(dir, "#{prefix}-#{stamp}.files")
      media = File.join(dir, "#{prefix}-#{stamp}.media.tar.gz")
      ctx.step("#{prefix} : base") do
        system.mkdir(dir)
        system.pg_dump(ctx.database, dump)
      end
      ctx.step("#{prefix} : pièces jointes") do
        plan = ctx.instance!("backup-plan", ["--list-file", list])
        ctx.journal["#{prefix}.media_root"] = plan["media_root"]?.try(&.as_s?) || ""
        missing = plan["missing"]?.try(&.as_a?).try(&.size) || 0
        ctx.log("#{missing} pièce(s) jointe(s) manquante(s) à signaler") if missing > 0
        system.tar_create(ctx.journal["#{prefix}.media_root"]? || "", list, media)
      end
      data = {
        "kind"       => kind,
        "path"       => dump,
        "media_path" => media,
        "size_bytes" => system.size(dump) + system.size(media),
        "sha256"     => system.sha256(dump),
        "version"    => system.current_release(ctx.slug) || ctx.param("version"),
        "taken_at"   => Time.parse(stamp, "%Y%m%dT%H%M%SZ", Time::Location::UTC).to_rfc3339,
      }
      json = JSON.parse(data.to_json)
      data.each { |key, value| ctx.set(key, value) } if ctx.task.kind == "backup.run"
      json
    end

    def self.prune(ctx : Context) : Nil
      ctx.list("paths").each do |path|
        ctx.step("effacer #{File.basename(path)}") { ctx.system.remove(path) }
      end
      ctx.set("pruned", ctx.list("paths").size)
    end

    # Restauration test : la sauvegarde est relue dans une base temporaire,
    # l'instance y répond (`status`), puis la base est supprimée. Prouve
    # qu'une sauvegarde se relit (ADR-008 D5).
    def self.test_restore(ctx : Context) : Nil
      system = ctx.system
      path = system.guard_backup_path!(ctx.param("path"))
      scratch = system.scratch_database(ctx.slug, ctx.task.id)
      unless ctx.param("sha256").empty? || system.sha256(path) == ctx.param("sha256")
        raise StepError.new("empreinte de la sauvegarde altérée : #{path}")
      end
      begin
        system.dropdb(scratch) if system.database_exists?(scratch)
        system.createdb(scratch)
        system.pg_restore(scratch, path)
        status = ctx.instance!("status", database: scratch)
        raise StepError.new("sauvegarde relue mais instance non provisionnée") unless status["provisioned"]?.try(&.as_bool?)
        media = ctx.param("media_path")
        raise StepError.new("archive des pièces illisible") unless media.empty? || system.tar_list?(media)
        ctx.set("version", status["version"]? || "")
        ctx.set("verified", true)
      ensure
        system.dropdb(scratch)
      end
    end

    # Restauration à une date : dans une instance neuve (`new`) ou en
    # remplacement (`replace`, après une sauvegarde de sûreté).
    def self.restore(ctx : Context) : Nil
      system = ctx.system
      path = system.guard_backup_path!(ctx.param("path"))
      media = ctx.param("media_path")
      if ctx.param("target") == "new"
        new_slug = ctx.param("new_slug")
        raise StepError.new("sous-domaine invalide : #{new_slug}", "usage") unless PartiduoAdmin::Protocol.valid_slug?(new_slug)
        database = system.database_for(new_slug)
        ctx.step("base neuve") do
          system.dropdb(database) if system.database_exists?(database)
          system.createdb(database)
          system.pg_restore(database, path)
        end
        ctx.step("fichiers de service") { system.render_instance(new_slug, ctx.param("new_host"), database, ctx.params) }
        ctx.set("database", database)
        ctx.set("version", ctx.instance!("status", database: database, slug_override: new_slug)["version"]? || "")
        return
      end
      safety = backup(ctx, "pre_restore", prefix: "pre-restore")
      ctx.result.clear
      ctx.set("safety_backup", safety)
      ctx.step("arrêt du service") { system.service(ctx.slug, "stop") }
      ctx.step("base remplacée") do
        system.dropdb(ctx.database)
        system.createdb(ctx.database)
        system.pg_restore(ctx.database, path)
      end
      ctx.step("pièces jointes") do
        root = ctx.journal["pre-restore.media_root"]?
        system.tar_extract(system.guard_backup_path!(media), root) if root && !root.empty? && !media.empty?
      end
      ctx.step("démarrage du service") { system.service(ctx.slug, "start") }
      ctx.set("version", ctx.instance!("status")["version"]? || "")
    end

    # --- Supervision ---------------------------------------------------------------

    def self.supervision(ctx : Context) : Nil
      system = ctx.system
      total, free = system.disk(system.config.backup_dir)
      ctx.set("disk", {"total_bytes" => total, "free_bytes" => free})
      entries = (ctx.params["dossiers"]?.try(&.as_a?) || [] of JSON::Any).map do |entry|
        slug = entry["slug"].as_s
        next unless PartiduoAdmin::Protocol.valid_slug?(slug)
        database = entry["database"]?.try(&.as_s?).presence || system.database_for(slug)
        reply = system.instance(slug, "status", ["--task", ctx.task.id.to_s], nil, database)
        {
          "slug"            => slug,
          "service"         => system.service(slug, "status"),
          "database"        => reply.ok? ? "ok" : (reply.exit_code == 6 ? "unavailable" : "error"),
          "version"         => reply.ok? ? (reply.data["version"]?.try(&.as_s?) || "") : "",
          "cert_expires_at" => system.cert_expiry(entry["host"]?.try(&.as_s?) || "").try(&.to_rfc3339),
        }
      end
      ctx.set("dossiers", entries.compact)
    end
  end
end
