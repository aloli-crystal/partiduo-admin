# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"
require "digest/sha256"
require "file_utils"

module PartiduoAgent
  # Échec d'une opération : `code` reprend, pour l'interface d'instance, la
  # catégorie de `error.code` (usage, refused, read_only…).
  class StepError < Exception
    getter code : String

    def initialize(message : String, @code : String = "failed")
      super(message)
    end
  end

  # Réponse de `partiduo-manage instance …` : une ligne JSON, un code de
  # sortie (partiduo-app, doc/api/instance-cli.adoc).
  record InstanceReply, exit_code : Int32, json : JSON::Any do
    def ok? : Bool
      exit_code == 0 && json["ok"]?.try(&.as_bool?) == true
    end

    def data : JSON::Any
      json["data"]? || JSON::Any.new({} of String => JSON::Any)
    end

    def error_code : String
      json["error"]?.try(&.["code"]?).try(&.as_s?) || "internal"
    end

    def message : String
      error = json["error"]?
      return "code #{exit_code}" if error.nil?
      "#{error["code"]?.try(&.as_s?)} #{error["reason"]?.try(&.as_s?)} — #{error["message"]?.try(&.as_s?)}"
    end
  end

  # Ce que l'exécutant sait faire sur un serveur. Trois réalisations : à
  # blanc (`DrySystem`), locale (`LocalSystem`, bases `partiduo_adm_*`,
  # services simulés par des fichiers) et production (`ProductionSystem`).
  # Chaque opération est idempotente ou vérifiable avant d'agir.
  abstract class System
    getter config : Config

    def initialize(@config : Config, @log : Proc(String, Nil))
    end

    def log(line : String) : Nil
      @log.call(line)
    end

    # Destination des lignes de journal (remplacée à chaque tâche).
    def sink=(sink : Proc(String, Nil)) : Nil
      @log = sink
    end

    # Nom de la base d'un dossier dans ce mode.
    def database_for(slug : String) : String
      PartiduoAdmin::Protocol.database_for(slug, local: config.local? || config.mode.dry_run?)
    end

    # Base temporaire d'une restauration test.
    def scratch_database(slug : String, task_id : Int64) : String
      "#{config.production? ? "partiduo_rt_" : "partiduo_adm_rt_"}#{slug.tr("-", "_")}_#{task_id}"[0, 63]
    end

    def backup_root(slug : String) : String
      File.join(config.backup_dir, slug)
    end

    # Paquet porté par les paramètres d'une tâche : `app` s'il est absent ;
    # toute autre valeur que `app` ou `devel` est refusée (elle choisit un
    # paquet, jamais un chemin).
    def self.package_of(params : JSON::Any) : String
      value = params["package"]?.try(&.as_s?) || ""
      return "app" if value.empty?
      raise StepError.new("paquet invalide : #{value}", "usage") unless PartiduoAdmin::Protocol.valid_package?(value)
      value
    end

    abstract def database_exists?(database : String) : Bool
    abstract def createdb(database : String) : Nil
    abstract def dropdb(database : String) : Nil
    abstract def provision(slug : String, domain : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
    # Fichiers de service d'une instance dont la base est déjà remplie
    # (restauration dans une instance neuve) : `partiduo-provision
    # --files-only`, nouveau port et nouvelle clé secrète.
    abstract def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
    abstract def install_instance(slug : String, host : String) : Bool
    # Interface en ligne de commande d'une instance. `package` (`app` ou
    # `devel`) : paquet dont l'outil `manage` est pris, seulement pour une
    # instance pas encore déclarée (création, instance neuve d'une
    # restauration) ; `nil` : celui qui sert déjà l'instance.
    abstract def instance(slug : String, action : String, args : Array(String), package : String? = nil,
                          database : String? = nil) : InstanceReply
    abstract def service(slug : String, command : String) : String
    abstract def pg_dump(database : String, path : String) : Nil
    abstract def pg_restore(database : String, path : String) : Nil
    abstract def pg_restore_list?(path : String) : Bool
    abstract def tar_create(slug : String, root : String, list_file : String, path : String) : Nil
    # Pièces jointes d'une sauvegarde remises sous le stockage de l'instance.
    abstract def tar_extract(slug : String, path : String) : Nil
    # Union de listes de pièces jointes (relevées avant et après `pg_dump`).
    abstract def merge_lists(sources : Array(String), destination : String) : Nil
    abstract def tar_list?(path : String) : Bool
    abstract def sha256(path : String) : String
    abstract def size(path : String) : Int64
    abstract def exists?(path : String) : Bool
    abstract def remove(path : String) : Nil
    abstract def mkdir(path : String) : Nil
    abstract def disk(path : String) : {Int64, Int64}
    abstract def cert_expiry(host : String) : Time?
    abstract def remove_instance(slug : String, host : String) : Nil

    # --- Sauvegardes chiffrées (D-CHF-004) : le clair passe par un tube
    # entre l'outil (`pg_dump`, `tar`, `pg_restore`) et l'exécutant, jamais
    # par le disque.
    abstract def pg_dump_sealed(database : String, path : String, sealer : BackupCrypto::Sealer) : Nil
    abstract def tar_create_sealed(slug : String, root : String, list_file : String, path : String,
                                   sealer : BackupCrypto::Sealer) : Nil
    abstract def pg_restore_sealed(database : String, path : String, keyring : Keyring) : Nil
    abstract def tar_extract_sealed(slug : String, path : String, keyring : Keyring) : Nil
    abstract def pg_restore_list_sealed?(path : String, keyring : Keyring) : Bool
    abstract def tar_list_sealed?(path : String, keyring : Keyring) : Bool
    # Authentifie tout le fichier, segment par segment (clé requise).
    abstract def verify_sealed(path : String, keyring : Keyring) : Nil
    # Sans clé : en-tête, empreinte de la clé, engagement, découpage.
    abstract def check_envelope(path : String, fingerprint : String, commitment : String) : Nil

    # Restauration d'une base, chiffrée ou non selon le nom du fichier.
    def restore_database(database : String, path : String, keyring : Keyring) : Nil
      BackupCrypto.sealed_path?(path) ? pg_restore_sealed(database, path, keyring) : pg_restore(database, path)
    end

    def restore_media(slug : String, path : String, keyring : Keyring) : Nil
      BackupCrypto.sealed_path?(path) ? tar_extract_sealed(slug, path, keyring) : tar_extract(slug, path)
    end

    def database_readable?(path : String, keyring : Keyring) : Bool
      BackupCrypto.sealed_path?(path) ? pg_restore_list_sealed?(path, keyring) : pg_restore_list?(path)
    end

    def media_readable?(path : String, keyring : Keyring) : Bool
      BackupCrypto.sealed_path?(path) ? tar_list_sealed?(path, keyring) : tar_list?(path)
    end

    # Un chemin de sauvegarde n'est accepté que sous `backup_dir` : aucune
    # tâche ne fait effacer un fichier ailleurs.
    #
    # Avec `slug` : sous le répertoire des sauvegardes *de ce dossier*
    # (D-CRA-001).
    def guard_backup_path!(path : String, slug : String? = nil) : String
      root = File.expand_path(slug ? backup_root(slug) : config.backup_dir)
      full = File.expand_path(path)
      if !full.starts_with?(root + "/") || path.includes?('\0')
        raise StepError.new("chemin hors du répertoire des sauvegardes#{slug ? " du dossier" : ""} : #{path}", "usage")
      end
      full
    end

    # Ligne sûre d'une liste de pièces jointes (`tar -C <racine> -T liste`) :
    # chemin relatif, sans `..`, sans caractère de contrôle. Toute autre
    # ligne ferait archiver un fichier hors du stockage de l'instance
    # (D-CRA-004).
    def self.safe_media_line?(line : String) : Bool
      return false if line.empty? || line.starts_with?('/') || line.starts_with?('-')
      return false if line.each_char.any?(&.control?)
      line.split('/').none? { |part| part == ".." || part.empty? }
    end

    # Dates de prise des archives d'un dossier (`archive-<horodatage>.dump`,
    # ou `.dump.enc` chiffrée, sous son répertoire de sauvegarde).
    def archive_dates(slug : String) : Array(Time)
      root = backup_root(slug)
      Dir.glob([File.join(root, "archive-*.dump"), File.join(root, "archive-*.dump.enc")]).compact_map do |path|
        PartiduoAdmin::Protocol.archive_taken_at(path)
      end
    end

    # Durée légale revérifiée par le serveur (D-CRA-007) : une suppression
    # définitive exige une archive du dossier, et la plus récente doit avoir
    # plus de dix ans. Une administration compromise ne supprime donc pas un
    # dossier avant son terme.
    def guard_retention!(slug : String, now : Time = Time.utc) : Nil
      latest = archive_dates(slug).max?
      raise StepError.new("aucune archive du dossier sur le serveur : suppression refusée", "refused") if latest.nil?
      if latest.shift(years: PartiduoAdmin::Protocol::ARCHIVE_RETENTION_YEARS) > now
        raise StepError.new("durée légale de conservation non écoulée (archive du #{latest.to_s("%Y-%m-%d")}) : " \
                            "suppression refusée", "refused")
      end
    end

    # Une archive encore dans sa durée légale n'est jamais effacée
    # (`backup.prune`, D-CRA-007).
    def guard_archive_removal!(path : String, now : Time = Time.utc) : Nil
      taken = PartiduoAdmin::Protocol.archive_taken_at(path) || return
      if taken.shift(years: PartiduoAdmin::Protocol::ARCHIVE_RETENTION_YEARS) > now
        raise StepError.new("archive dans sa durée légale de conservation : #{File.basename(path)}", "refused")
      end
    end

    # Courriel remis par le serveur (`--mail-command`, D-CRA-003).
    def mailer? : Bool
      !config.mail_command.strip.empty?
    end

    def deliver_invitation(email : String, host : String, url : String, locale : String) : Nil
      raise StepError.new("adresse d'invitation refusée", "usage") unless InvitationMail.valid_address?(email)
      raise StepError.new("expéditeur des courriels manquant (--mail-from)", "usage") if config.mail_from.empty?
      send_mail(email, InvitationMail.build(config.mail_from, email, host, url, locale.presence || "fr"))
      # Le lien n'est jamais écrit au journal renvoyé à l'administration.
      log("invitation remise par le serveur à #{email}")
    end

    # Commande de courriel lancée sans shell ; message sur l'entrée standard.
    def send_mail(recipient : String, message : String) : Nil
      argv = config.mail_command.split(' ', remove_empty: true) + [recipient]
      stderr = IO::Memory.new
      status = Process.run(argv[0], argv[1..], input: IO::Memory.new(message), output: Process::Redirect::Close,
        error: stderr)
      raise StepError.new("courriel non remis (code #{status.exit_code}) : #{stderr.to_s.strip[0, 200]?}") unless status.success?
    rescue ex : File::NotFoundError | IO::Error
      raise StepError.new("courriel non remis : #{ex.message}")
    end

    # Sortie d'erreur d'un outil, pour le journal renvoyé à l'administration :
    # sans les lignes de PostgreSQL qui citent des valeurs de la base
    # (`DETAIL`, `CONTEXT`, `Command was`, `LINE`…), ADR-008 D3 (D-CRA-005).
    def self.redact_errors(text : String) : String
      text.lines.reject do |line|
        line.lstrip.starts_with?("DETAIL:") || line.lstrip.starts_with?("CONTEXT:") ||
          line.lstrip.starts_with?("Command was:") || line.lstrip.starts_with?("LINE ") ||
          line.lstrip.starts_with?("HINT:") || line.lstrip.starts_with?("QUERY:") || line.lstrip.starts_with?("^")
      end.join('\n')
    end
  end

  # À blanc : état simulé en mémoire, chaque geste écrit au journal.
  class DrySystem < System
    # Pièces simulées et leurs dépendances (forme de `status`).
    DRY_CATALOG = {
      "ACCOUNTING" => [] of String, "INVOICING" => [] of String, "ANALYTIC" => ["ACCOUNTING"],
      "STOCK" => ["ACCOUNTING|INVOICING"], "FOLLOWUP" => ["ACCOUNTING|INVOICING"], "EINVOICING" => ["INVOICING"],
    }

    getter databases = Set(String).new
    getter provisioned = Set(String).new
    getter stopped = Set(String).new
    getter files = {} of String => Int64
    # Paquet de chaque instance simulée (sous-domaine → `app` ou `devel`).
    getter packages = {} of String => String
    getter read_only = Set(String).new
    getter calls = [] of String
    # Version du contrat que simule l'instance (`version`, `status`, toute
    # réponse) : la version courante de partiduo-app, ou une plus ancienne
    # pour éprouver un repli.
    property contract = "1.1.0"
    # Version (semver) que rend l'instance simulée.
    property version = "0.1.0"

    private def op(name : String, detail : String) : Nil
      calls << "#{name} #{detail}"
      log("[à blanc] #{name} #{detail}")
      if (fail = config.fail_on) && "#{name} #{detail}".includes?(fail)
        config.fail_on = nil
        raise StepError.new("échec simulé : #{name} #{detail}")
      end
    end

    def database_exists?(database : String) : Bool
      databases.includes?(database)
    end

    def createdb(database : String) : Nil
      op("createdb", database)
      databases << database
    end

    def dropdb(database : String) : Nil
      op("dropdb", database)
      databases.delete(database)
    end

    def provision(slug : String, domain : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
      package = System.package_of(params)
      op("partiduo-provision", "#{slug} #{database} #{package}")
      databases << database
      provisioned << database
      packages[slug] = package
      "== Instance #{slug} provisionnée.\nInvitation : https://#{slug}.#{domain}/invitation/DRYRUNTOKEN\n"
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      package = System.package_of(params)
      op("partiduo-provision --files-only", "#{slug} #{database} #{package}")
      packages[slug] = package
      "== Instance #{slug} provisionnée.\n"
    end

    def install_instance(slug : String, host : String) : Bool
      op("install", host)
      false
    end

    def instance(slug : String, action : String, args : Array(String), package : String? = nil,
                 database : String? = nil) : InstanceReply
      if package && !PartiduoAdmin::Protocol.valid_package?(package)
        raise StepError.new("paquet invalide : #{package}", "usage")
      end
      op("instance #{action}", ([slug] + args.reject(&.starts_with?("--requested-by"))).join(' '))
      db = database || database_for(slug)
      if action == "status" && !databases.includes?(db)
        return InstanceReply.new(6, JSON.parse(%({"ok":false,"error":{"code":"database_unavailable","reason":"database.unavailable","message":"base injoignable"}})))
      end
      data = dry_data(slug, action, args, db, version)
      InstanceReply.new(0, JSON.parse({"contract" => contract, "action" => action, "ok" => true, "data" => data}.to_json))
    end

    # Réponse simulée de l'interface d'instance, pour une base qui répond.
    private def dry_data(slug : String, action : String, args : Array(String), db : String, version : String)
      case action
      when "version" then {"version" => version, "contract" => contract}
      when "status"
        {"version" => version, "contract" => contract, "provisioned" => provisioned.includes?(db),
         "read_only" => {"active" => read_only.includes?(db)}, "migrations" => {"applied" => 10, "pending" => 0},
         "modules" => DRY_CATALOG.map { |code, depends| {"code" => code, "depends_on" => depends} }}
      when "read-only"
        args.first? == "on" ? read_only << db : read_only.delete(db)
        {"read_only" => {"active" => read_only.includes?(db)}, "restart_required" => false}
      when "backup-plan"
        {"media_root" => "/dry-run/media/#{slug}", "file_count" => 0, "total_bytes" => 0, "missing" => [] of String}
      when "admin-invite"
        {"email" => args.first? || "", "user_created" => false, "url" => "https://dry-run/invitation/DRYRUN",
         "expires_at" => "2026-10-05T00:00:00Z", "usable_admins" => 0,
         "approval_mode" => args.index("--approval-mode").try { |index| args[index + 1]? } || "dual"}
      else {"code" => args.first? || "", "active" => action == "enable", "data" => "kept"}
      end
    end

    def service(slug : String, command : String) : String
      op("service #{command}", slug) unless command == "status"
      case command
      when "stop"  then stopped << slug
      when "start" then stopped.delete(slug)
      end
      stopped.includes?(slug) ? "stopped" : "running"
    end

    def pg_dump(database : String, path : String) : Nil
      op("pg_dump", "#{database} #{path}")
      files[path] = 4096_i64
    end

    def pg_restore(database : String, path : String) : Nil
      op("pg_restore", "#{path} #{database}")
      provisioned << database
    end

    def pg_restore_list?(path : String) : Bool
      op("pg_restore --list", path)
      files.has_key?(path) || true
    end

    def tar_create(slug : String, root : String, list_file : String, path : String) : Nil
      op("tar", path)
      files[path] = 512_i64
    end

    def tar_extract(slug : String, path : String) : Nil
      op("tar -x", "#{path} #{slug}")
    end

    def merge_lists(sources : Array(String), destination : String) : Nil
      op("listes", destination)
    end

    # Fichiers chiffrés simulés : mode de chaque fichier.
    getter sealed = {} of String => String

    def pg_dump_sealed(database : String, path : String, sealer : BackupCrypto::Sealer) : Nil
      op("pg_dump | chiffrement #{sealer.mode_name}", "#{database} #{path}")
      files[path] = 4096_i64
      sealed[path] = sealer.mode_name
    end

    def tar_create_sealed(slug : String, root : String, list_file : String, path : String,
                          sealer : BackupCrypto::Sealer) : Nil
      op("tar | chiffrement #{sealer.mode_name}", path)
      files[path] = 512_i64
      sealed[path] = sealer.mode_name
    end

    def pg_restore_sealed(database : String, path : String, keyring : Keyring) : Nil
      op("déchiffrement | pg_restore", "#{path} #{database}")
      provisioned << database
    end

    def tar_extract_sealed(slug : String, path : String, keyring : Keyring) : Nil
      op("déchiffrement | tar -x", "#{path} #{slug}")
    end

    def pg_restore_list_sealed?(path : String, keyring : Keyring) : Bool
      op("déchiffrement | pg_restore --list", path)
      true
    end

    def tar_list_sealed?(path : String, keyring : Keyring) : Bool
      op("déchiffrement | tar -t", path)
      true
    end

    def verify_sealed(path : String, keyring : Keyring) : Nil
      op("authentification", path)
    end

    def check_envelope(path : String, fingerprint : String, commitment : String) : Nil
      op("enveloppe", path)
    end

    def tar_list?(path : String) : Bool
      op("tar -t", path)
      true
    end

    def sha256(path : String) : String
      Digest::SHA256.hexdigest("dry-run:#{path}")
    end

    def size(path : String) : Int64
      files[path]? || 0_i64
    end

    def exists?(path : String) : Bool
      files.has_key?(path)
    end

    # Archives simulées : fichiers connus du système à blanc.
    def archive_dates(slug : String) : Array(Time)
      root = backup_root(slug) + "/"
      files.keys.select(&.starts_with?(root)).compact_map { |path| PartiduoAdmin::Protocol.archive_taken_at(path) }
    end

    # Courriels remis à blanc : destinataire et message (specs).
    getter mails = [] of {String, String}

    def send_mail(recipient : String, message : String) : Nil
      op("courriel", recipient)
      mails << {recipient, message}
    end

    # Même garde-fou qu'en production : un essai à blanc refuse ce que le
    # serveur refuserait.
    def remove(path : String) : Nil
      full = guard_backup_path!(path)
      op("rm", full)
      files.delete(path)
    end

    def mkdir(path : String) : Nil
    end

    def disk(path : String) : {Int64, Int64}
      {100_000_000_000_i64, 60_000_000_000_i64}
    end

    def cert_expiry(host : String) : Time?
      nil
    end

    def remove_instance(slug : String, host : String) : Nil
      op("retrait", host)
      stopped << slug
    end
  end

  # Mode local : vraies bases `partiduo_adm_*` et vrais outils PostgreSQL,
  # sans vhost, systemd ni Let's Encrypt — les fichiers de service sont
  # produits dans `work_dir`, et l'arrêt d'un service est un fichier témoin.
  class LocalSystem < System
    DATABASE = /\A[a-z_][a-z0-9_]{0,62}\z/

    # Base de partiduo-admin (ADR-008 D1).
    ADMIN_DATABASE = "partiduo_admin"

    def instances_dir : String
      File.join(config.work_dir, "instances")
    end

    def instance_dir(slug : String) : String
      File.join(instances_dir, slug)
    end

    # Garde-fou du mode local : aucune autre base que `partiduo_adm_*`.
    def guard_database!(database : String) : Nil
      raise StepError.new("nom de base invalide : #{database}", "usage") unless DATABASE.matches?(database)
      prefix = config.production? ? "partiduo_" : "partiduo_adm_"
      unless database.starts_with?(prefix)
        raise StepError.new("base refusée (#{prefix}* seulement) : #{database}", "usage")
      end
      # La base de l'administration elle-même n'est jamais celle d'un dossier.
      raise StepError.new("base refusée : #{database}", "usage") if database == ADMIN_DATABASE
    end

    def pg_env : Hash(String, String)
      {"PGHOST" => config.pg_socket}
    end

    # Exécute un programme (jamais un shell) ; journalise la commande.
    def run(argv : Array(String), env = {} of String => String, chdir : String? = nil, quiet : Bool = false) : {Int32, String, String}
      log("+ #{argv.map { |arg| arg.includes?(' ') ? "'#{arg}'" : arg }.join(' ')}") unless quiet
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(argv[0], argv[1..], env: env, chdir: chdir, output: stdout, error: stderr)
      {status.exit_code, stdout.to_s, stderr.to_s}
    rescue ex : File::NotFoundError | IO::Error
      raise StepError.new("#{argv[0]} : #{ex.message}")
    end

    def run!(argv : Array(String), env = {} of String => String, chdir : String? = nil) : String
      code, output, err = run(argv, env, chdir)
      raise StepError.new("#{File.basename(argv[0])} (code #{code}) : #{System.redact_errors(err).strip[0, 500]? || ""}") unless code == 0
      output
    end

    def database_exists?(database : String) : Bool
      guard_database!(database)
      _, output, _ = run(["psql", "-d", "postgres", "-tAc", "SELECT 1 FROM pg_database WHERE datname = '#{database}'"], pg_env, quiet: true)
      output.strip == "1"
    end

    def createdb(database : String) : Nil
      guard_database!(database)
      run!(["createdb", "--encoding=UTF8", database], pg_env)
    end

    def dropdb(database : String) : Nil
      guard_database!(database)
      run!(["dropdb", "--if-exists", database], pg_env)
    end

    def provision(slug : String, domain : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
      guard_database!(database)
      package = System.package_of(params)
      argv = provision_for(package) + ["--manage", manage_for(package).join(' '), "--domain", domain, "--database", database,
                                       "--pg-socket", config.pg_socket, "--output-dir", instances_dir] +
             company_options(params) + module_options(params)
      argv += ["--acme-email", config.acme_email] unless config.acme_email.empty?
      argv << "--acme-staging" if config.acme_staging
      argv << "--skip-createdb" if skip_createdb
      argv << slug
      Dir.mkdir_p(instances_dir)
      output = run!(argv, pg_env)
      declare_package(slug, package)
      output
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      guard_database!(database)
      package = System.package_of(params)
      argv = provision_for(package) + ["--files-only", "--manage", manage_for(package).join(' '), "--domain", domain,
                                       "--database", database, "--pg-socket", config.pg_socket,
                                       "--output-dir", instances_dir] + module_options(params)
      argv += ["--locale", locale(params), slug]
      Dir.mkdir_p(instances_dir)
      output = run!(argv, pg_env)
      declare_package(slug, package)
      output
    end

    # Société : options de `partiduo-provision` (valeurs passées telles
    # quelles, en arguments séparés : jamais par un shell).
    def company_options(params : JSON::Any) : Array(String)
      options = ["--name", params["name"]?.try(&.as_s?) || "", "--regime", params["regime"]?.try(&.as_s?) || "",
                 "--locale", locale(params), "--admin-email", params["admin_email"]?.try(&.as_s?) || ""]
      if siren = params["siren"]?.try(&.as_s?).presence
        options += ["--siren", siren]
      end
      if vat = params["vat"]?.try(&.as_s?).presence
        options += ["--vat", vat]
      end
      options
    end

    def module_options(params : JSON::Any) : Array(String)
      modules = params["modules"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
      extensions = params["extensions"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
      unless (modules + extensions).all? { |code| PartiduoAdmin::Protocol::CODE.matches?(code) }
        raise StepError.new("code de module ou d'extension invalide", "usage")
      end
      options = ["--modules", modules.join(',')]
      options += ["--with", extensions.join(',')] unless extensions.empty?
      options
    end

    def locale(params : JSON::Any) : String
      value = params["locale"]?.try(&.as_s?).presence || "fr"
      %w[fr en nl].includes?(value) ? value : "fr"
    end

    # Mode local : rien n'est installé ; les fichiers restent dans work_dir.
    def install_instance(slug : String, host : String) : Bool
      log("mode local : fichiers de service laissés dans #{instance_dir(slug)} (ni systemd, ni vhost, ni certificat)")
      false
    end

    # Environnement de l'instance : son fichier `.env` produit par
    # partiduo-provision (mode local).
    def instance_env(slug : String) : Hash(String, String)
      env = {} of String => String
      file = File.join(instance_dir(slug), "#{slug}.env")
      if File.exists?(file)
        File.each_line(file) do |line|
          next if line.starts_with?('#') || !line.includes?('=')
          key, value = line.split('=', 2)
          env[key.strip] = value.strip.lchop('"').rchop('"')
        end
      end
      env
    end

    # Outils du paquet en mode local : `--manage` et `--provision` pour
    # `app`, `--manage-devel` et `--provision-devel` pour `devel` (à défaut,
    # ceux de `app`, signalé au journal).
    def manage_for(package : String?) : Array(String)
      command = config.manage
      if package == "devel"
        command = config.manage_devel.presence || begin
          log("mode local : --manage-devel non fourni, partiduo-manage de app utilisé pour devel")
          config.manage
        end
      end
      command.split(' ', remove_empty: true)
    end

    def provision_for(package : String) : Array(String)
      command = package == "devel" ? config.provision_devel.presence || config.provision : config.provision
      command.split(' ', remove_empty: true)
    end

    # Mode local : le paquet d'une instance, retenu à son provisionnement
    # (en production, c'est la déclaration de l'instance sur le serveur).
    def package_file(slug : String) : String
      File.join(instance_dir(slug), "PACKAGE")
    end

    def declare_package(slug : String, package : String) : Nil
      Dir.mkdir_p(instance_dir(slug))
      File.write(package_file(slug), package)
    end

    def declared_package(slug : String) : String?
      file = package_file(slug)
      value = File.exists?(file) ? File.read(file).strip : ""
      PartiduoAdmin::Protocol.valid_package?(value) ? value : nil
    end

    def instance(slug : String, action : String, args : Array(String), package : String? = nil,
                 database : String? = nil) : InstanceReply
      if package && !PartiduoAdmin::Protocol.valid_package?(package)
        raise StepError.new("paquet invalide : #{package}", "usage")
      end
      env = instance_env(slug)
      # Mode local : pièces jointes sous work_dir, pas sous l'arborescence
      # de production que porte le fichier d'environnement.
      env["PARTIDUO_MEDIA_ROOT"] = File.join(instance_dir(slug), "media") unless config.production?
      env["DATABASE_URL"] = "postgres:///#{database}?host=#{config.pg_socket}" if database
      if db_url = env["DATABASE_URL"]?
        guard_database!(URI.parse(db_url).path.lchop('/'))
      else
        env["DATABASE_URL"] = "postgres:///#{database_for(slug)}?host=#{config.pg_socket}"
      end
      argv = manage_for(package || declared_package(slug)) + ["instance", action] + args
      code, output, errors = run(argv, env)
      InstanceReply.new(code, JSON.parse(reply_line(output, errors)))
    end

    # Dernière ligne JSON de la sortie ; à défaut, une erreur qui porte le
    # début de la sortie d'erreur (diagnostic dans le journal de la tâche).
    def reply_line(output : String, errors : String) : String
      output.lines.reverse!.find(&.starts_with?('{')) ||
        {"ok" => false, "error" => {"code" => "internal", "message" => "réponse illisible : #{System.redact_errors(errors).strip[0, 300]?}"}}.to_json
    end

    def marker(slug : String) : String
      File.join(instance_dir(slug), "SUSPENDED")
    end

    def service(slug : String, command : String) : String
      Dir.mkdir_p(instance_dir(slug))
      case command
      when "stop"
        log("mode local : arrêt du service simulé (#{marker(slug)})")
        File.write(marker(slug), Time.utc.to_rfc3339)
      when "start"
        log("mode local : démarrage du service simulé")
        File.delete(marker(slug)) if File.exists?(marker(slug))
      end
      File.exists?(marker(slug)) ? "stopped" : "running"
    end

    def pg_dump(database : String, path : String) : Nil
      guard_database!(database)
      Dir.mkdir_p(File.dirname(path))
      run!(["pg_dump", "-Fc", "--no-owner", "-f", path, database], pg_env)
    end

    def pg_restore(database : String, path : String) : Nil
      guard_database!(database)
      run!(["pg_restore", "--no-owner", "--exit-on-error", "-d", database, path], pg_env)
    end

    def pg_restore_list?(path : String) : Bool
      code, _, _ = run(["pg_restore", "--list", path], pg_env)
      code == 0
    end

    def tar_create(slug : String, root : String, list_file : String, path : String) : Nil
      Dir.mkdir_p(File.dirname(path))
      if !Dir.exists?(root) || File.size(list_file).zero?
        # Aucune pièce jointe : archive vide, pour une sauvegarde homogène.
        run!(["tar", "-czf", path, "-T", "/dev/null"])
      else
        run!(["tar", "-C", root, "-czf", path, "-T", list_file])
      end
    end

    # Mode local : stockage de l'instance sous work_dir (voir `instance`).
    def tar_extract(slug : String, path : String) : Nil
      root = File.join(instance_dir(slug), "media")
      Dir.mkdir_p(root)
      run!(["tar", "-C", root, "-xzf", guard_backup_path!(path)])
    end

    def merge_lists(sources : Array(String), destination : String) : Nil
      lines = sources.flat_map { |source| File.exists?(source) ? File.read_lines(source) : [] of String }
      lines = lines.reject(&.empty?)
      unsafe = lines.reject { |line| System.safe_media_line?(line) }
      log("#{unsafe.size} ligne(s) de pièce jointe écartée(s) : chemin hors du stockage") unless unsafe.empty?
      File.write(guard_backup_path!(destination), (lines - unsafe).uniq!.sort!.join { |line| "#{line}\n" })
      sources.each { |source| File.delete(source) if File.exists?(source) }
    end

    def tar_list?(path : String) : Bool
      code, _, _ = run(["tar", "-tzf", path])
      code == 0
    end

    # --- Sauvegardes chiffrées ------------------------------------------------

    # Commandes des flux : sortie ou entrée standard, jamais un fichier en
    # clair (la production les fait passer par l'enveloppe de sudo).
    def dump_argv(database : String) : Array(String)
      ["pg_dump", "-Fc", "--no-owner", database]
    end

    def restore_argv(database : String) : Array(String)
      ["pg_restore", "--no-owner", "--exit-on-error", "-d", database]
    end

    def media_archive_argv(slug : String, root : String, list_file : String) : Array(String)
      if !Dir.exists?(root) || !File.exists?(list_file) || File.size(list_file).zero?
        # Aucune pièce jointe : archive vide, pour une sauvegarde homogène.
        ["tar", "-czf", "-", "-T", "/dev/null"]
      else
        ["tar", "-C", root, "-czf", "-", "-T", list_file]
      end
    end

    def media_restore_argv(slug : String) : Array(String)
      root = File.join(instance_dir(slug), "media")
      Dir.mkdir_p(root)
      ["tar", "-C", root, "-xzf", "-"]
    end

    # Programme dont l'entrée ou la sortie standard est un flux ; rend le
    # code de sortie et la sortie d'erreur. Jamais de shell.
    def run_stream(argv : Array(String), env = {} of String => String, input : IO? = nil,
                   output : IO? = nil) : {Int32, String}
      log("+ #{argv.map { |arg| arg.includes?(' ') ? "'#{arg}'" : arg }.join(' ')}#{input ? " < déchiffrement" : ""}#{output ? " > chiffrement" : ""}")
      stderr = IO::Memory.new
      begin
        status = Process.run(argv[0], argv[1..], env: env, input: input || Process::Redirect::Close,
          output: output || Process::Redirect::Close, error: stderr)
        {status.exit_code, stderr.to_s}
      rescue ex : IO::Error
        # Tube rompu : l'outil s'est arrêté avant la fin du flux.
        {-1, "#{stderr} (#{ex.message})"}
      end
    rescue ex : File::NotFoundError
      raise StepError.new("#{argv[0]} : #{ex.message}")
    end

    # Sortie d'un programme chiffrée dans `path` (fichier `.part` renommé à
    # la fin : jamais de sauvegarde incomplète sous son nom définitif).
    def seal_output(argv : Array(String), path : String, sealer : BackupCrypto::Sealer, env = {} of String => String) : Nil
      full = guard_backup_path!(path)
      partial = "#{full}.part"
      begin
        Dir.mkdir_p(File.dirname(full))
        writer = sealer.writer(File.open(partial, "wb", perm: 0o640))
        code, errors = begin
          run_stream(argv, env, output: writer)
        ensure
          writer.close
        end
        unless code == 0
          raise StepError.new("#{File.basename(argv.find(&.starts_with?("pg_dump")) || argv[0])} (code #{code}) : " \
                              "#{System.redact_errors(errors).strip[0, 500]? || ""}")
        end
        File.rename(partial, full)
      rescue ex : File::Error | IO::Error
        raise StepError.new("sauvegarde chiffrée non écrite : #{ex.message}")
      ensure
        # Échec : aucun fichier partiel ne reste.
        File.delete(partial) if File.exists?(partial)
      end
    end

    # Fichier déchiffré en flux vers l'entrée d'un programme.
    def unseal_input(argv : Array(String), path : String, keyring : Keyring, env = {} of String => String) : {Int32, String}
      keyring.open(guard_backup_path!(path)) { |reader| run_stream(argv, env, input: reader) }
    end

    def pg_dump_sealed(database : String, path : String, sealer : BackupCrypto::Sealer) : Nil
      guard_database!(database)
      seal_output(dump_argv(database), path, sealer, pg_env)
    end

    def tar_create_sealed(slug : String, root : String, list_file : String, path : String,
                          sealer : BackupCrypto::Sealer) : Nil
      seal_output(media_archive_argv(slug, root, list_file), path, sealer)
    end

    def pg_restore_sealed(database : String, path : String, keyring : Keyring) : Nil
      guard_database!(database)
      code, errors = unseal_input(restore_argv(database), path, keyring, pg_env)
      raise StepError.new("pg_restore (code #{code}) : #{System.redact_errors(errors).strip[0, 500]? || ""}") unless code == 0
    end

    def tar_extract_sealed(slug : String, path : String, keyring : Keyring) : Nil
      code, errors = unseal_input(media_restore_argv(slug), path, keyring)
      raise StepError.new("tar (code #{code}) : #{errors.strip[0, 500]? || ""}") unless code == 0
    end

    def pg_restore_list_sealed?(path : String, keyring : Keyring) : Bool
      code, _ = unseal_input(["pg_restore", "--list"], path, keyring, pg_env)
      code == 0
    end

    def tar_list_sealed?(path : String, keyring : Keyring) : Bool
      code, _ = unseal_input(["tar", "-tzf", "-"], path, keyring)
      code == 0
    end

    def verify_sealed(path : String, keyring : Keyring) : Nil
      log("authentification de #{File.basename(path)}")
      keyring.open(guard_backup_path!(path)) do |reader|
        buffer = Bytes.new(BackupCrypto::CHUNK_SIZE)
        while reader.read(buffer) > 0
        end
      end
    end

    def check_envelope(path : String, fingerprint : String, commitment : String) : Nil
      log("enveloppe de #{File.basename(path)} : structure, empreinte de la clé, engagement")
      BackupCrypto.check_structure(guard_backup_path!(path), fingerprint, commitment)
    rescue ex : BackupCrypto::Error
      raise StepError.new("enveloppe de #{File.basename(path)} : #{ex.message}", "refused")
    end

    def sha256(path : String) : String
      Digest::SHA256.new.file(path).hexfinal
    end

    def size(path : String) : Int64
      File.size(path).to_i64
    end

    def exists?(path : String) : Bool
      File.exists?(path)
    end

    def remove(path : String) : Nil
      full = guard_backup_path!(path)
      log("+ rm #{full}")
      File.delete(full) if File.exists?(full)
    end

    def mkdir(path : String) : Nil
      Dir.mkdir_p(path)
    end

    def disk(path : String) : {Int64, Int64}
      Dir.mkdir_p(path)
      _, output, _ = run(["df", "-Pk", path], quiet: true)
      fields = output.lines.last?.try(&.split) || [] of String
      total = (fields[1]?.try(&.to_i64?) || 0_i64) * 1024
      free = (fields[3]?.try(&.to_i64?) || 0_i64) * 1024
      {total, free}
    end

    def cert_expiry(host : String) : Time?
      nil
    end

    def remove_instance(slug : String, host : String) : Nil
      log("mode local : fichiers de #{slug} retirés de #{instance_dir(slug)}")
      FileUtils.rm_rf(instance_dir(slug))
    end
  end

  # Production : tout geste privilégié passe par deux scripts enveloppes
  # possédés par root (`deploy/libexec/`, D-AFN-002), seuls permis par
  # sudoers et qui valident eux-mêmes leurs arguments :
  #
  # * `partiduo-agent-root` (en root) : installation et retrait d'une
  #   instance, démarrage et arrêt de son service, certificat ;
  # * `partiduo-agent-instance` (sous le compte des instances) : interface
  #   d'instance, `partiduo-provision`, bases (création, suppression,
  #   `pg_dump`, `pg_restore`), pièces jointes.
  #
  # Les bases et leurs objets appartiennent ainsi au rôle de l'instance
  # (`partiduo`), celui qui les fait tourner (D-AFN-005). L'exécutant ne
  # passe que des valeurs : sous-domaine, nom de base, paquet, chemins sous
  # le répertoire des sauvegardes ; les enveloppes calculent le reste de
  # leur propre configuration (`/etc/partiduo-agent/helpers.conf`).
  class ProductionSystem < LocalSystem
    def root_helper : String
      File.join(config.helpers_dir, "partiduo-agent-root")
    end

    def instance_helper : String
      File.join(config.helpers_dir, "partiduo-agent-instance")
    end

    def as_root(args : Array(String)) : Array(String)
      ["sudo", "-n", root_helper] + args
    end

    def as_instance(args : Array(String)) : Array(String)
      ["sudo", "-n", "-u", config.system_user, instance_helper] + args
    end

    def instances_dir : String
      File.join(config.state_dir, "instances")
    end

    private def guard_slug!(slug : String) : Nil
      raise StepError.new("sous-domaine invalide : #{slug}", "usage") unless PartiduoAdmin::Protocol.valid_slug?(slug)
    end

    def database_exists?(database : String) : Bool
      guard_database!(database)
      code, _, errors = run(as_instance(["db-exists", database]), quiet: true)
      return true if code == 0
      return false if code == 3
      raise StepError.new("db-exists (code #{code}) : #{errors.strip[0, 300]?}")
    end

    def createdb(database : String) : Nil
      guard_database!(database)
      run!(as_instance(["createdb", database]))
    end

    def dropdb(database : String) : Nil
      guard_database!(database)
      run!(as_instance(["dropdb", database]))
    end

    # `partiduo-provision` sous le compte des instances : domaine, rôle
    # propriétaire, socket, racines et gabarits viennent de la
    # configuration de l'enveloppe ; la base est celle du sous-domaine.
    def provision(slug : String, domain : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
      guard_slug!(slug)
      guard_database!(database)
      raise StepError.new("base refusée : #{database}", "usage") unless database == database_for(slug)
      argv = ["provision", slug] + company_options(params) + module_options(params) + package_option(params)
      argv << "--skip-createdb" if skip_createdb
      run!(as_instance(argv))
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      guard_slug!(slug)
      raise StepError.new("base refusée : #{database}", "usage") unless database == database_for(slug)
      run!(as_instance(["provision", slug, "--files-only", "--locale", locale(params)] + module_options(params) +
                       package_option(params)))
    end

    # Paquet qui servira l'instance : toujours transmis (`app` par défaut),
    # jamais une autre valeur que `app` ou `devel`.
    private def package_option(params : JSON::Any) : Array(String)
      ["--package", System.package_of(params)]
    end

    def install_instance(slug : String, host : String) : Bool
      guard_slug!(slug)
      before = cert_exists?(host)
      run!(as_root(["install", slug]))
      !before && cert_exists?(host) && !config.acme_staging
    end

    def cert_exists?(host : String) : Bool
      code, _, _ = run(as_root(["cert", host, "exists"]), quiet: true)
      code == 0
    end

    # `-` pour le paquet : l'enveloppe prend celui qui sert déjà l'instance.
    def instance(slug : String, action : String, args : Array(String), package : String? = nil,
                 database : String? = nil) : InstanceReply
      guard_slug!(slug)
      guard_database!(database) if database
      if package && !PartiduoAdmin::Protocol.valid_package?(package)
        raise StepError.new("paquet invalide : #{package}", "usage")
      end
      argv = as_instance(["cli", slug, database || "-", package || "-", action] + args)
      code, output, errors = run(argv)
      InstanceReply.new(code, JSON.parse(reply_line(output, errors)))
    end

    def service(slug : String, command : String) : String
      guard_slug!(slug)
      run!(as_root(["service", slug, command])) unless command == "status"
      code, _, _ = run(["systemctl", "is-active", "--quiet", "partiduo-#{slug}.service"], quiet: true)
      code == 0 ? "running" : "stopped"
    end

    def pg_dump(database : String, path : String) : Nil
      guard_database!(database)
      run!(as_instance(["dump", database, guard_backup_path!(path)]))
    end

    def pg_restore(database : String, path : String) : Nil
      guard_database!(database)
      run!(as_instance(["restore", database, guard_backup_path!(path)]))
    end

    # Répertoire de sauvegarde d'un dossier, créé par l'enveloppe (groupe de
    # l'exécutant, écriture pour les deux comptes).
    def mkdir(path : String) : Nil
      slug = File.basename(path)
      unless File.expand_path(path) == File.expand_path(backup_root(slug))
        raise StepError.new("répertoire refusé : #{path}", "usage")
      end
      guard_slug!(slug)
      run!(as_instance(["backup-dir", slug]))
    end

    def tar_create(slug : String, root : String, list_file : String, path : String) : Nil
      run!(as_instance(["media-archive", slug, guard_backup_path!(list_file), guard_backup_path!(path)]))
    end

    def tar_extract(slug : String, path : String) : Nil
      run!(as_instance(["media-restore", slug, guard_backup_path!(path)]))
    end

    # Flux chiffrés : l'enveloppe écrit sur sa sortie standard ou lit son
    # entrée standard (`-`) ; le clair ne touche pas le disque (D-CHF-004).
    def dump_argv(database : String) : Array(String)
      as_instance(["dump", database, "-"])
    end

    def restore_argv(database : String) : Array(String)
      as_instance(["restore", database, "-"])
    end

    def media_archive_argv(slug : String, root : String, list_file : String) : Array(String)
      guard_slug!(slug)
      as_instance(["media-archive", slug, guard_backup_path!(list_file), "-"])
    end

    def media_restore_argv(slug : String) : Array(String)
      guard_slug!(slug)
      as_instance(["media-restore", slug, "-"])
    end

    def cert_expiry(host : String) : Time?
      return if host.empty?
      code, output, _ = run(as_root(["cert", host, "enddate"]), quiet: true)
      return unless code == 0
      Time.parse(output.strip.sub("notAfter=", ""), "%b %e %H:%M:%S %Y %Z", Time::Location::UTC)
    rescue Time::Format::Error
      nil
    end

    def remove_instance(slug : String, host : String) : Nil
      guard_slug!(slug)
      run!(as_root(["remove", slug]))
    end
  end
end
