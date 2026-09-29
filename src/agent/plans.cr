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
    getter keyring : Keyring

    def initialize(@task : TaskInfo, @system : System, @journal : Journal)
      @keyring = Keyring.new(system.config, journal, task.data_keys, ->(line : String) { system.log(line) })
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

    # Version de partiduo-app portée par un paramètre : vide, ou une version
    # publiée (`Protocol::VERSION`) ; jamais un chemin.
    def release(key : String) : String
      value = param(key)
      unless value.empty? || PartiduoAdmin::Protocol.valid_version?(value)
        raise StepError.new("version invalide : #{value}", "usage")
      end
      value
    end

    def slug : String
      value = param("slug")
      raise StepError.new("sous-domaine invalide : #{value}", "usage") unless PartiduoAdmin::Protocol.valid_slug?(value)
      value
    end

    # Domaine des dossiers du serveur : celui de la configuration de
    # l'exécutant (obligatoire en production) ; à défaut (modes local et à
    # blanc), celui de la tâche, vérifié. Un domaine de tâche différent de
    # celui de la configuration est refusé.
    def domain : String
      configured = system.config.domain
      given = param("domain")
      if !configured.empty? && !given.empty? && given != configured
        raise StepError.new("domaine refusé : #{given} (serveur : #{configured})", "usage")
      end
      value = configured.presence || given
      raise StepError.new("domaine invalide : #{value}", "usage") unless PartiduoAdmin::Protocol.valid_domain?(value)
      value
    end

    # Hôte d'un dossier : toujours calculé (`<sous-domaine>.<domaine>`) ;
    # l'hôte reçu, s'il y en a un, doit être celui-là (D-AFN-004).
    def host_for(slug : String, key : String = "host") : String
      expected = "#{slug}.#{domain}"
      given = param(key)
      raise StepError.new("hôte refusé : #{given} (attendu : #{expected})", "usage") unless given.empty? || given == expected
      expected
    end

    def host : String
      host_for(slug)
    end

    # Base du dossier : toujours celle du sous-domaine dans ce mode ; la base
    # reçue de l'administration, s'il y en a une, doit être celle-là
    # (D-AFN-004). Une tâche forgée ne vise donc jamais la base d'un autre
    # dossier.
    def database : String
      expected = system.database_for(slug)
      given = param("database")
      raise StepError.new("base refusée : #{given} (attendue : #{expected})", "usage") unless given.empty? || given == expected
      expected
    end

    # Chemin de sauvegarde reçu de l'administration : sous le répertoire des
    # sauvegardes *du dossier* (`<backup_dir>/<sous-domaine>/`), jamais celui
    # d'un autre. Une tâche forgée ne restaure donc pas la base d'un dossier
    # dans un autre, ni n'efface les sauvegardes d'un autre (D-CRA-001).
    def own_backup!(path : String, of_slug : String = slug) : String
      system.guard_backup_path!(path, of_slug)
    end

    # Valeur reçue de l'administration et passée en argument à
    # `manage instance` : jamais prise pour une option (`--list-file=…`),
    # jamais sur plusieurs lignes (D-CRA-002).
    def value_arg(key : String) : String
      value = param(key)
      if value.starts_with?('-') || value.includes?('\n') || value.includes?('\r') || value.includes?('\0')
        raise StepError.new("valeur refusée pour #{key}", "usage")
      end
      value
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
      # Tâche d'un dossier : sous-domaine, hôte et base vérifiés avant tout
      # geste (D-AFN-004).
      unless ctx.task.kind == "supervision.check"
        ctx.host
        ctx.database
      end
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
      database = ctx.database
      host = ctx.host
      check_contract(ctx, ctx.release("version").presence)
      ctx.step("provisionnement") do
        exists = system.database_exists?(database)
        provisioned = exists && ctx.instance("status", database: database).data["provisioned"]?.try(&.as_bool?) == true
        if provisioned
          ctx.log("base #{database} déjà provisionnée : rien à refaire")
        else
          output = system.provision(ctx.slug, ctx.domain, ctx.params, database, skip_createdb: exists)
          if link = output.match(/https?:\/\/\S+\/invitation\/\S+/)
            ctx.journal["invitation_url"] = link[0]
          end
        end
        system.switch_release(ctx.slug, ctx.release("version")) unless ctx.release("version").empty?
      end
      ctx.step("installation") do
        ctx.journal["certificate"] = system.install_instance(ctx.slug, host).to_s
      end
      status = ctx.instance!("status", database: database)
      raise StepError.new("instance non provisionnée après création", "refused") unless status["provisioned"]?.try(&.as_bool?)
      ctx.set("database", database)
      ctx.set("version", status["version"]?.try(&.as_s?) || "")
      if url = ctx.journal["invitation_url"]?
        if ctx.system.mailer?
          # Lien remis par le serveur lui-même (D-CRA-003).
          ctx.step("invitation") do
            ctx.system.deliver_invitation(ctx.param("admin_email"), host, url, ctx.param("locale"))
          end
          ctx.set("invitation_delivered", "server")
        else
          ctx.set("invitation_url", url)
        end
      end
      ctx.set("certificate", {"issued" => ctx.journal["certificate"]? == "true", "staging" => system.config.acme_staging})
    end

    # --- Modules et extensions (ADR-006 D2 : désactiver conserve les données)

    # Ordre des gestes selon les dépendances que rend `status`
    # (`depends_on`) : une pièce se désactive après celles qui la requièrent,
    # s'active après celles qu'elle requiert (`Modules.deactivate` et
    # `activate` refusent sinon). Sans dépendance connue, l'ordre reçu est
    # gardé (l'admin met déjà les extensions avant les modules à la
    # désactivation, après à l'activation).
    def self.modules(ctx : Context) : Nil
      check_contract(ctx)
      depends = dependencies(ctx.instance!("status"))
      disable_order(ctx.list("disable"), depends).each do |code|
        ctx.step("désactiver #{code}") { ctx.instance!("disable", [code]) }
      end
      enable_order(ctx.list("enable"), depends).each do |code|
        ctx.step("activer #{code}") { ctx.instance!("enable", [code]) }
      end
      status = ctx.instance!("status")
      ctx.set("modules", status["modules"]? || [] of String)
    end

    alias Depends = Hash(String, Array(String))

    # Dépendances par pièce (codes en majuscules ; une alternative `A|B`
    # compte ses deux membres).
    def self.dependencies(status : JSON::Any) : Depends
      depends = Depends.new
      (status["modules"]?.try(&.as_a?) || [] of JSON::Any).each do |piece|
        code = piece["code"]?.try(&.as_s?) || next
        list = piece["depends_on"]?.try(&.as_a?).try(&.compact_map(&.as_s?)) || [] of String
        depends[code.upcase] = list.flat_map(&.split('|')).map(&.upcase)
      end
      depends
    end

    # Pièces requises d'abord.
    def self.enable_order(codes : Array(String), depends : Depends) : Array(String)
      ordered = [] of String
      codes.each { |code| visit(code, codes, depends, false, ordered, Set(String).new) }
      ordered
    end

    # Pièces qui requièrent les autres d'abord.
    def self.disable_order(codes : Array(String), depends : Depends) : Array(String)
      ordered = [] of String
      codes.each { |code| visit(code, codes, depends, true, ordered, Set(String).new) }
      ordered
    end

    private def self.requires?(code : String, other : String, depends : Depends) : Bool
      (depends[code.upcase]? || [] of String).includes?(other.upcase)
    end

    # Parcours en profondeur : passent avant `code` les codes qu'il requiert
    # (`dependents` faux) ou ceux qui le requièrent (`dependents` vrai) ;
    # un cycle est ignoré.
    private def self.visit(code : String, codes : Array(String), depends : Depends, dependents : Bool,
                           ordered : Array(String), path : Set(String)) : Nil
      return if ordered.includes?(code) || path.includes?(code)
      path << code
      codes.each do |other|
        next if other == code
        first = dependents ? requires?(other, code, depends) : requires?(code, other, depends)
        visit(other, codes, depends, dependents, ordered, path) if first
      end
      path.delete(code)
      ordered << code
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
        # Chiffrée : relue avec la clé de données que la tâche vient de
        # tirer (journal), y compris pour la clé du cabinet (D-CHF-007).
        path = data["path"].as_s
        raise StepError.new("archive illisible : #{path}") unless ctx.system.database_readable?(path, ctx.keyring)
        raise StepError.new("empreinte de l'archive altérée") unless ctx.system.sha256(path) == data["sha256"].as_s
        media = data["media_path"].as_s
        raise StepError.new("archive des pièces illisible") unless media.empty? || ctx.system.media_readable?(media, ctx.keyring)
      end
      ctx.step("arrêt du service") { ctx.system.service(ctx.slug, "stop") }
      verified = data.as_h.merge({"verified" => JSON::Any.new(true)})
      ctx.result.clear
      ctx.set("backup", verified)
    end

    # Restauration d'une archive en instance active : base recréée depuis
    # l'archive si elle a disparu, lecture seule levée, service démarré.
    def self.restore_archive(ctx : Context) : Nil
      path = ctx.param("path")
      path = ctx.own_backup!(path) unless path.empty?
      ctx.step("base") do
        unless ctx.system.database_exists?(ctx.database)
          raise StepError.new("base absente et aucune archive fournie", "usage") if path.empty?
          ctx.system.createdb(ctx.database)
          ctx.system.restore_database(ctx.database, path, ctx.keyring)
        end
      end
      ctx.step("lecture seule levée") { ctx.instance!("read-only", ["off", "--reason", "restauration de l'archive"]) }
      ctx.step("démarrage du service") { ctx.system.service(ctx.slug, "start") }
      ctx.set("version", ctx.instance!("status")["version"]? || "")
    end

    # Suppression définitive (après la durée légale et la validation, à une
    # ou deux personnes, vérifiées par l'admin) : service et fichiers
    # retirés, base supprimée, sauvegardes effacées.
    def self.delete(ctx : Context) : Nil
      # Chemins vérifiés avant tout geste : une liste qui vise un autre
      # dossier n'a rien retiré (D-CRA-001).
      backups = ctx.list("backups").map { |path| ctx.own_backup!(path) }
      ctx.system.guard_retention!(ctx.slug)
      ctx.log("suppression définitive — #{approval_line(ctx)}")
      ctx.step("retrait du service") { ctx.system.remove_instance(ctx.slug, ctx.host) }
      ctx.step("suppression de la base") { ctx.system.dropdb(ctx.database) }
      ctx.step("suppression des sauvegardes") do
        backups.each { |path| ctx.system.remove(path) }
      end
      ctx.set("deleted", true)
    end

    # --- Montée de version (sauvegarde préalable, retour arrière) --------------

    # Le service est arrêté AVANT la sauvegarde préalable : rien n'est écrit
    # entre la sauvegarde et un éventuel retour arrière (D-AFN-007). Tout
    # échec, prévu (`StepError`) ou non (clé absente, réponse illisible,
    # erreur de fichier), déclenche le retour arrière.
    def self.upgrade(ctx : Context) : Nil
      target = ctx.release("version")
      from = ctx.release("from_version").presence || ctx.system.current_release(ctx.slug) || ""
      raise StepError.new("version cible manquante", "usage") if target.empty?
      check_contract(ctx, target)
      backup_data : JSON::Any? = nil
      begin
        ctx.step("arrêt du service") { ctx.system.service(ctx.slug, "stop") }
        backup_data = backup(ctx, "pre_upgrade", prefix: "pre-upgrade")
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
      rescue error
        ctx.log("échec : #{error.message} — retour arrière vers #{from}")
        code = error.is_a?(StepError) ? error.code : "internal"
        begin
          rollback(ctx, target, from, backup_data)
        rescue ex
          raise StepError.new("montée vers #{target} échouée (#{error.message}) ; retour arrière incomplet : " \
                              "#{ex.message}", "internal")
        end
        ctx.result.clear
        ctx.set("backup", backup_data) if backup_data
        ctx.set("rolled_back", true)
        ctx.set("version", from)
        # Le dossier est revenu à son état d'avant : une reprise repartira
        # de zéro, sauvegarde comprise.
        ctx.journal.reset
        raise StepError.new("montée vers #{target} échouée, retour à #{from} : #{error.message}", code)
      end
    end

    def self.rollback(ctx : Context, target : String, from : String, backup_data : JSON::Any?) : Nil
      system = ctx.system
      system.service(ctx.slug, "stop")
      system.switch_release(ctx.slug, from) unless from.empty?
      if ctx.journal.done?("migrations") || ctx.journal.done?("bascule vers #{target}")
        # Migrations peut-être en partie appliquées : la base revient à la
        # sauvegarde préalable, prise service arrêté.
        path = backup_data.try(&.["path"]?).try(&.as_s?) || raise StepError.new("sauvegarde préalable introuvable")
        system.dropdb(ctx.database)
        system.createdb(ctx.database)
        system.restore_database(ctx.database, path, ctx.keyring)
      end
      system.service(ctx.slug, "start")
    end

    # --- Opérations sensibles : mode de validation (D-VAL2-005) --------------

    # Mode reçu : `single` ou `dual` ; absent, `dual` (administration
    # antérieure à l'API 1.2.0). Toute autre valeur est refusée.
    def self.approval_mode(ctx : Context) : String
      mode = ctx.param("approval_mode").presence || "dual"
      raise StepError.new("mode de validation refusé : #{mode}", "usage") unless PartiduoAdmin::Protocol::APPROVAL_MODES.includes?(mode)
      mode
    end

    # Personnes cohérentes avec le mode : exactement une pour `single`, au
    # moins deux distinctes pour `dual` ; aucune valeur prise pour une
    # option ni séparateur (D-CRA-002).
    def self.checked_approvers(ctx : Context) : Array(String)
      approvers = ctx.list("approvers").map(&.strip)
      if approvers.any? { |approver| approver.empty? || approver.starts_with?('-') || approver.includes?(',') || approver.includes?('\n') }
        raise StepError.new("valeur refusée pour approvers", "usage")
      end
      distinct = approvers.map(&.downcase).uniq!.size
      case approval_mode(ctx)
      when "single"
        raise StepError.new("validation à une personne : un seul nom attendu", "usage") unless approvers.size == 1
      else
        raise StepError.new("validation à deux personnes incomplète", "usage") unless distinct >= 2
      end
      approvers
    end

    # Ligne du journal : mode, référence et personnes.
    def self.approval_line(ctx : Context) : String
      approvers = checked_approvers(ctx)
      label = approval_mode(ctx) == "single" ? "validation à une personne" : "validation à deux personnes"
      "#{label} #{ctx.param("approval_ref")} par #{approvers.join(", ")}"
    end

    # --- Recours d'accès (décision prise dans l'admin) -----------------------

    def self.admin_invite(ctx : Context) : Nil
      check_contract(ctx)
      approvers = checked_approvers(ctx)
      ctx.log("recours d'accès — #{approval_line(ctx)}")
      # Une personne : le contrat 1.0.0 de l'instance exige deux noms ; le
      # second dit qu'il n'y en a pas eu (D-VAL2-005, B-VAL2-001).
      approvers += [PartiduoAdmin::Protocol::SINGLE_APPROVER_MARK] if approval_mode(ctx) == "single"
      data = ctx.instance!("admin-invite", [ctx.value_arg("email"), "--reason", ctx.value_arg("reason"),
                                            "--approval-ref", ctx.value_arg("approval_ref"),
                                            "--approvers", approvers.join(',')])
      %w[email user_created expires_at usable_admins].each { |key| ctx.result[key] = data[key] if data[key]? }
      url = data["url"]?.try(&.as_s?)
      if url && ctx.system.mailer?
        # Lien remis par le serveur lui-même : il ne passe jamais par
        # l'administration (D-CRA-003).
        ctx.system.deliver_invitation(data["email"]?.try(&.as_s?) || ctx.param("email"), ctx.host, url, ctx.param("locale"))
        ctx.set("invitation_delivered", "server")
      elsif url
        ctx.result["url"] = JSON::Any.new(url)
      end
    end

    # --- Sauvegardes -------------------------------------------------------------

    # `pg_dump -Fc` et archive des pièces jointes (liste de `backup-plan`),
    # empreinte SHA-256. Noms figés au premier passage : une reprise
    # réutilise les mêmes fichiers.
    #
    # Chiffrement (`encryption` des paramètres, D-CHF-001) : aucun, clé du
    # serveur ou clé publique du cabinet. Chiffrées, la base et les pièces
    # jointes partagent une clé de données et portent l'extension `.enc` ;
    # le clair ne passe que par un tube (D-CHF-004).
    def self.backup(ctx : Context, kind : String, prefix : String = "backup") : JSON::Any
      system = ctx.system
      stamp = ctx.journal["#{prefix}.stamp"]? || (ctx.journal["#{prefix}.stamp"] = Time.utc.to_s("%Y%m%dT%H%M%SZ"))
      sealer = sealer(ctx, prefix)
      suffix = sealer ? BackupCrypto::EXTENSION : ""
      dir = system.backup_root(ctx.slug)
      dump = File.join(dir, "#{prefix}-#{stamp}.dump#{suffix}")
      list = File.join(dir, "#{prefix}-#{stamp}.files")
      media = File.join(dir, "#{prefix}-#{stamp}.media.tar.gz#{suffix}")
      # Pièces jointes relevées avant ET après pg_dump : l'archive porte
      # l'union des deux listes, donc toute pièce que la base sauvegardée
      # peut citer, même déposée ou supprimée pendant la sauvegarde
      # (D-AFN-012).
      ctx.step("#{prefix} : liste des pièces jointes") do
        system.mkdir(dir)
        ctx.instance!("backup-plan", ["--list-file", "#{list}.before"])
      end
      ctx.step("#{prefix} : base") do
        sealer ? system.pg_dump_sealed(ctx.database, dump, sealer) : system.pg_dump(ctx.database, dump)
      end
      ctx.step("#{prefix} : pièces jointes") do
        plan = ctx.instance!("backup-plan", ["--list-file", "#{list}.after"])
        root = plan["media_root"]?.try(&.as_s?) || ""
        missing = plan["missing"]?.try(&.as_a?).try(&.size) || 0
        ctx.log("#{missing} pièce(s) jointe(s) manquante(s) à signaler") if missing > 0
        system.merge_lists(["#{list}.before", "#{list}.after"], list)
        sealer ? system.tar_create_sealed(ctx.slug, root, list, media, sealer) : system.tar_create(ctx.slug, root, list, media)
      end
      data = {
        "kind"         => kind,
        "path"         => dump,
        "media_path"   => media,
        "size_bytes"   => system.size(dump) + system.size(media),
        "sha256"       => system.sha256(dump),
        "media_sha256" => system.sha256(media),
        "version"      => system.current_release(ctx.slug) || ctx.param("version"),
        "taken_at"     => Time.parse(stamp, "%Y%m%dT%H%M%SZ", Time::Location::UTC).to_rfc3339,
        "encryption"   => sealer.try(&.describe) || {"mode" => "none"},
      }
      json = JSON.parse(data.to_json)
      data.each { |key, value| ctx.set(key, value) } if ctx.task.kind == "backup.run"
      json
    end

    # Clé de données de la sauvegarde `prefix` et son enveloppe, tirées au
    # premier passage et retenues dans le journal : une reprise chiffre la
    # suite avec la même clé. La clé de données (`secret.*`) est effacée du
    # journal à la fin de la tâche ; une reprise après un échec qui ne peut
    # plus la retrouver (clé du cabinet) reprend la sauvegarde depuis la base.
    def self.sealer(ctx : Context, prefix : String) : BackupCrypto::Sealer?
      settings = ctx.params["encryption"]?
      mode = settings.try(&.["mode"]?).try(&.as_s?) || "none"
      return if mode == "none"
      raise StepError.new("mode de chiffrement inconnu : #{mode}", "usage") unless %w[server cabinet].includes?(mode)
      if resumed = resumed_sealer(ctx, prefix, mode)
        return resumed
      end
      journal = ctx.journal
      sealer = if mode == "server"
                 BackupCrypto::Sealer.server(ctx.keyring.server_key)
               else
                 BackupCrypto::Sealer.cabinet(cabinet_key(settings))
               end
      journal["#{prefix}.mode"] = mode
      journal["#{prefix}.key_id"] = sealer.key_id.hexstring
      journal["#{prefix}.wrapped"] = Base64.strict_encode(sealer.wrapped)
      journal["#{Keyring::SECRET_PREFIX}#{prefix}.data_key"] = Base64.strict_encode(sealer.data_key)
      ctx.log("#{prefix} : chiffrement #{mode == "server" ? "par la clé du serveur" : "par la clé du cabinet"} " \
              "(empreinte #{sealer.key_id.hexstring[0, 16]}…)")
      sealer
    end

    # Reprise : l'enveloppe et la clé de données du premier passage (clé du
    # serveur : la clé de données se retrouve en la déchiffrant). Sans elle,
    # la base et les pièces jointes sont à reprendre.
    def self.resumed_sealer(ctx : Context, prefix : String, mode : String) : BackupCrypto::Sealer?
      journal = ctx.journal
      wrapped = journal["#{prefix}.wrapped"]?
      return unless wrapped && journal["#{prefix}.mode"]? == mode
      data_key = journal["#{Keyring::SECRET_PREFIX}#{prefix}.data_key"]?.try { |value| Base64.decode(value) }
      if data_key.nil? && mode == "server"
        data_key = ctx.keyring.server_key.unwrap(Base64.decode(wrapped)) rescue nil
      end
      if data_key
        key_id = journal["#{prefix}.key_id"]?.try(&.hexbytes?) || raise StepError.new("journal de reprise incomplet")
        return BackupCrypto::Sealer.new(mode == "server" ? BackupCrypto::SERVER : BackupCrypto::CABINET, key_id,
          Base64.decode(wrapped), data_key)
      end
      ctx.log("#{prefix} : clé de données oubliée, sauvegarde reprise depuis la base")
      journal.unmark("#{prefix} : base")
      journal.unmark("#{prefix} : pièces jointes")
      nil
    end

    # Clé publique du cabinet reçue de l'administration ; son empreinte doit
    # être celle annoncée (une clé altérée en chemin est refusée).
    def self.cabinet_key(settings : JSON::Any?) : BackupCrypto::PublicKey
      pem = settings.try(&.["public_key"]?).try(&.as_s?) || ""
      raise StepError.new("clé publique du cabinet manquante", "usage") if pem.empty?
      key = BackupCrypto::PublicKey.new(pem)
      expected = settings.try(&.["key_fingerprint"]?).try(&.as_s?) || ""
      unless expected.empty? || expected == key.fingerprint
        raise StepError.new("clé publique du cabinet : empreinte #{key.fingerprint[0, 16]}… au lieu de #{expected[0, 16]}…", "usage")
      end
      key
    rescue ex : BackupCrypto::Error
      raise StepError.new("clé publique du cabinet : #{ex.message}", "usage")
    end

    def self.prune(ctx : Context) : Nil
      paths = ctx.list("paths").map { |path| ctx.own_backup!(path) }
      paths.each { |path| ctx.system.guard_archive_removal!(path) }
      paths.each do |path|
        ctx.step("effacer #{File.basename(path)}") { ctx.system.remove(path) }
      end
      ctx.set("pruned", ctx.list("paths").size)
    end

    # Description de la sauvegarde lue (`backup_encryption`) : mode,
    # empreinte de la clé, engagement sur la clé de données.
    record SourceEnvelope, mode : String, fingerprint : String, commitment : String do
      def sealed? : Bool
        mode != "none"
      end
    end

    def self.source_envelope(ctx : Context, path : String) : SourceEnvelope
      info = ctx.params["backup_encryption"]?
      mode = info.try(&.["mode"]?).try(&.as_s?) || (BackupCrypto.sealed_path?(path) ? "unknown" : "none")
      if (mode == "none") == BackupCrypto.sealed_path?(path)
        raise StepError.new("sauvegarde #{File.basename(path)} : chiffrement annoncé « #{mode} » incohérent avec le fichier", "usage")
      end
      SourceEnvelope.new(mode, info.try(&.["key_fingerprint"]?).try(&.as_s?) || "",
        info.try(&.["commitment"]?).try(&.as_s?) || "")
    end

    # Empreintes SHA-256 des fichiers de la sauvegarde, calculées sur les
    # fichiers tels que conservés (chiffrés s'ils le sont).
    def self.check_digests(ctx : Context, path : String, media : String) : Nil
      system = ctx.system
      unless ctx.param("sha256").empty? || system.sha256(path) == ctx.param("sha256")
        raise StepError.new("empreinte de la sauvegarde altérée : #{path}")
      end
      unless media.empty? || ctx.param("media_sha256").empty? || system.sha256(media) == ctx.param("media_sha256")
        raise StepError.new("empreinte de l'archive des pièces jointes altérée : #{media}")
      end
    end

    # Clé de la sauvegarde disponible : toujours pour la clé du serveur,
    # pour la clé du cabinet seulement si l'admin du cabinet l'a fournie.
    def self.readable?(ctx : Context, source : SourceEnvelope) : Bool
      source.mode != "cabinet" || !ctx.keyring.data_key?(source.commitment).nil?
    end

    # Restauration test : la sauvegarde est relue dans une base temporaire,
    # l'instance y répond (`status`), puis la base est supprimée. Prouve
    # qu'une sauvegarde se relit (ADR-008 D5).
    #
    # Chiffrée par la clé du cabinet sans que sa clé soit fournie : le
    # serveur ne peut pas la lire (D-CHF-007) ; seules l'empreinte SHA-256
    # et l'intégrité de l'enveloppe (en-tête, clé attendue, engagement,
    # découpage) sont vérifiées, et le résultat le dit.
    def self.test_restore(ctx : Context) : Nil
      system = ctx.system
      path = ctx.own_backup!(ctx.param("path"))
      media = ctx.param("media_path")
      media = ctx.own_backup!(media) unless media.empty?
      scratch = system.scratch_database(ctx.slug, ctx.task.id)
      source = source_envelope(ctx, path)
      check_digests(ctx, path, media)
      unless readable?(ctx, source)
        system.check_envelope(path, source.fingerprint, source.commitment)
        system.check_envelope(media, source.fingerprint, source.commitment) unless media.empty?
        ctx.log("contenu vérifiable seulement avec la clé du cabinet : empreinte et enveloppe vérifiées")
        ctx.set("verified", false)
        ctx.set("envelope_verified", true)
        ctx.set("check", "envelope")
        return
      end
      begin
        system.dropdb(scratch) if system.database_exists?(scratch)
        system.createdb(scratch)
        system.restore_database(scratch, path, ctx.keyring)
        status = ctx.instance!("status", database: scratch)
        raise StepError.new("sauvegarde relue mais instance non provisionnée") unless status["provisioned"]?.try(&.as_bool?)
        raise StepError.new("archive des pièces illisible") unless media.empty? || system.media_readable?(media, ctx.keyring)
        ctx.set("version", status["version"]? || "")
        ctx.set("verified", true)
        ctx.set("check", "full")
      ensure
        system.dropdb(scratch)
      end
    end

    # Restauration à une date : dans une instance neuve (`new`) ou en
    # remplacement (`replace`, après une sauvegarde de sûreté). Chiffrée,
    # la sauvegarde est d'abord authentifiée en entier : rien n'est
    # remplacé par un fichier altéré ou avec une mauvaise clé.
    def self.restore(ctx : Context) : Nil
      system = ctx.system
      path = ctx.own_backup!(ctx.param("path"))
      media = ctx.param("media_path")
      media = ctx.own_backup!(media) unless media.empty?
      source = source_envelope(ctx, path)
      check_digests(ctx, path, media)
      if source.sealed?
        unless readable?(ctx, source)
          raise StepError.new("sauvegarde chiffrée par la clé du cabinet : la restauration exige que l'admin du " \
                              "cabinet fournisse sa clé", "key_required")
        end
        ctx.step("authentification de la sauvegarde") do
          system.verify_sealed(path, ctx.keyring)
          system.verify_sealed(media, ctx.keyring) unless media.empty?
        end
      end
      ctx.param("target") == "new" ? restore_new(ctx, path, media) : restore_replace(ctx, path, media)
    end

    # Instance neuve : base restaurée, fichiers de service produits par
    # `partiduo-provision --files-only` (nouveau port, nouvelle clé
    # secrète), installation comme à la création (service, vhost,
    # certificat compté dans le quota), pièces jointes (D-AFN-009).
    def self.restore_new(ctx : Context, path : String, media : String) : Nil
      system = ctx.system
      new_slug = ctx.param("new_slug")
      raise StepError.new("sous-domaine invalide : #{new_slug}", "usage") unless PartiduoAdmin::Protocol.valid_slug?(new_slug)
      raise StepError.new("instance neuve identique à la source", "usage") if new_slug == ctx.slug
      host = ctx.host_for(new_slug, "new_host")
      database = system.database_for(new_slug)
      ctx.step("base neuve") do
        system.dropdb(database) if system.database_exists?(database)
        system.createdb(database)
        system.restore_database(database, path, ctx.keyring)
      end
      ctx.step("fichiers de service") { system.provision_files(new_slug, ctx.domain, ctx.params, database) }
      ctx.step("installation") do
        ctx.journal["certificate"] = system.install_instance(new_slug, host).to_s
        version = ctx.release("version")
        system.switch_release(new_slug, version) unless version.empty?
      end
      ctx.step("pièces jointes") { system.restore_media(new_slug, media, ctx.keyring) unless media.empty? }
      ctx.set("database", database)
      ctx.set("version", ctx.instance!("status", database: database, slug_override: new_slug)["version"]? || "")
      ctx.set("certificate", {"issued" => ctx.journal["certificate"]? == "true", "staging" => system.config.acme_staging})
    end

    # Remplacement : service arrêté AVANT la sauvegarde de sûreté (rien
    # n'est écrit entre les deux), base puis pièces jointes remplacées.
    # Un échec avant le remplacement de la base redémarre le service.
    def self.restore_replace(ctx : Context, path : String, media : String) : Nil
      system = ctx.system
      begin
        ctx.step("arrêt du service") { system.service(ctx.slug, "stop") }
        safety = backup(ctx, "pre_restore", prefix: "pre-restore")
        ctx.result.clear
        ctx.set("safety_backup", safety)
      rescue error
        system.service(ctx.slug, "start")
        raise error
      end
      ctx.step("base remplacée") do
        system.dropdb(ctx.database)
        system.createdb(ctx.database)
        system.restore_database(ctx.database, path, ctx.keyring)
      end
      ctx.step("pièces jointes") { system.restore_media(ctx.slug, media, ctx.keyring) unless media.empty? }
      ctx.step("démarrage du service") { system.service(ctx.slug, "start") }
      ctx.set("version", ctx.instance!("status")["version"]? || "")
    end

    # --- Supervision ---------------------------------------------------------------

    # Une entrée mal formée ou dont l'hôte ou la base ne correspondent pas
    # au sous-domaine est ignorée (et journalisée) : elle ne fait pas
    # échouer la supervision des autres dossiers du serveur.
    def self.supervision(ctx : Context) : Nil
      system = ctx.system
      total, free = system.disk(system.config.backup_dir)
      ctx.set("disk", {"total_bytes" => total, "free_bytes" => free})
      entries = (ctx.params["dossiers"]?.try(&.as_a?) || [] of JSON::Any).compact_map do |entry|
        supervise(ctx, entry)
      end
      ctx.set("dossiers", entries)
    end

    def self.supervise(ctx : Context, entry : JSON::Any) : Hash(String, String?)?
      system = ctx.system
      slug = entry.as_h?.try(&.["slug"]?).try(&.as_s?) || ""
      unless PartiduoAdmin::Protocol.valid_slug?(slug)
        ctx.log("supervision : entrée ignorée (sous-domaine invalide)")
        return
      end
      database = system.database_for(slug)
      host = supervised_host(ctx, slug, entry)
      given_database = entry["database"]?.try(&.as_s?) || ""
      if host.nil? || !(given_database.empty? || given_database == database)
        ctx.log("supervision : #{slug} ignoré (hôte ou base sans rapport avec le sous-domaine)")
        return
      end
      reply = system.instance(slug, "status", ["--task", ctx.task.id.to_s], nil, database)
      {
        "slug"            => slug,
        "service"         => system.service(slug, "status"),
        "database"        => database_state(reply),
        "version"         => reply.ok? ? (reply.data["version"]?.try(&.as_s?) || "") : "",
        "cert_expires_at" => (host.empty? ? nil : system.cert_expiry(host)).try(&.to_rfc3339),
      }
    rescue error : StepError
      ctx.log("supervision : #{slug} en erreur (#{error.message})")
      nil
    end

    private def self.database_state(reply : InstanceReply) : String
      return "ok" if reply.ok?
      reply.exit_code == 6 ? "unavailable" : "error"
    end

    # Hôte d'un dossier supervisé : `<sous-domaine>.<domaine>` (domaine de
    # l'exécutant, sinon de la tâche) ; l'hôte reçu doit être celui-là.
    # `nil` si l'entrée désigne un autre hôte ; chaîne vide si aucun n'est
    # connu (pas de relevé de certificat).
    private def self.supervised_host(ctx : Context, slug : String, entry : JSON::Any) : String?
      given = entry["host"]?.try(&.as_s?) || ""
      domain = ctx.system.config.domain.presence || ctx.param("domain").presence
      expected = domain ? "#{slug}.#{domain}" : given
      return unless given.empty? || given == expected
      return expected if expected.empty?
      expected.starts_with?("#{slug}.") && PartiduoAdmin::Protocol.valid_domain?(expected) ? expected : nil
    end
  end
end
