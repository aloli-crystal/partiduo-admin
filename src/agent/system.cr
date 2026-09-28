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

    abstract def database_exists?(database : String) : Bool
    abstract def createdb(database : String) : Nil
    abstract def dropdb(database : String) : Nil
    abstract def provision(slug : String, domain : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
    # Fichiers de service d'une instance dont la base est déjà remplie
    # (restauration dans une instance neuve) : `partiduo-provision
    # --files-only`, nouveau port et nouvelle clé secrète.
    abstract def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
    abstract def install_instance(slug : String, host : String) : Bool
    abstract def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                          database : String? = nil) : InstanceReply
    abstract def service(slug : String, command : String) : String
    abstract def switch_release(slug : String, version : String) : Nil
    abstract def current_release(slug : String) : String?
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

    # Un chemin de sauvegarde n'est accepté que sous `backup_dir` : aucune
    # tâche ne fait effacer un fichier ailleurs.
    def guard_backup_path!(path : String) : String
      root = File.expand_path(config.backup_dir)
      full = File.expand_path(path)
      raise StepError.new("chemin hors du répertoire des sauvegardes : #{path}", "usage") unless full.starts_with?(root + "/")
      full
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
    getter releases = {} of String => String
    getter read_only = Set(String).new
    getter calls = [] of String

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
      op("partiduo-provision", "#{slug} #{database}")
      databases << database
      provisioned << database
      releases[slug] = params["version"]?.try(&.as_s?).presence || "0.1.0"
      "== Instance #{slug} provisionnée.\nInvitation : https://#{slug}.#{domain}/invitation/DRYRUNTOKEN\n"
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      op("partiduo-provision --files-only", "#{slug} #{database}")
      "== Instance #{slug} provisionnée.\n"
    end

    def install_instance(slug : String, host : String) : Bool
      op("install", host)
      false
    end

    def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                 database : String? = nil) : InstanceReply
      op("instance #{action}", ([slug] + args.reject(&.starts_with?("--requested-by"))).join(' '))
      db = database || database_for(slug)
      if action == "status" && !databases.includes?(db)
        return InstanceReply.new(6, JSON.parse(%({"ok":false,"error":{"code":"database_unavailable","reason":"database.unavailable","message":"base injoignable"}})))
      end
      data = dry_data(slug, action, args, db, version || releases[slug]? || "0.1.0")
      InstanceReply.new(0, JSON.parse({"contract" => "1.0.0", "action" => action, "ok" => true, "data" => data}.to_json))
    end

    # Réponse simulée de l'interface d'instance, pour une base qui répond.
    private def dry_data(slug : String, action : String, args : Array(String), db : String, version : String)
      case action
      when "version" then {"version" => version, "contract" => "1.0.0"}
      when "status"
        {"version" => version, "contract" => "1.0.0", "provisioned" => provisioned.includes?(db),
         "read_only" => {"active" => read_only.includes?(db)}, "migrations" => {"applied" => 10, "pending" => 0},
         "modules" => DRY_CATALOG.map { |code, depends| {"code" => code, "depends_on" => depends} }}
      when "read-only"
        args.first? == "on" ? read_only << db : read_only.delete(db)
        {"read_only" => {"active" => read_only.includes?(db)}, "restart_required" => false}
      when "backup-plan"
        {"media_root" => "/dry-run/media/#{slug}", "file_count" => 0, "total_bytes" => 0, "missing" => [] of String}
      when "admin-invite"
        {"email" => args.first? || "", "user_created" => false, "url" => "https://dry-run/invitation/DRYRUN",
         "expires_at" => "2026-10-05T00:00:00Z", "usable_admins" => 0}
      when "migrate" then {"applied" => [] of String, "pending" => 0}
      else                {"code" => args.first? || "", "active" => action == "enable", "data" => "kept"}
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

    def switch_release(slug : String, version : String) : Nil
      op("release", "#{slug} #{version}")
      releases[slug] = version
    end

    def current_release(slug : String) : String?
      releases[slug]?
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
      raise StepError.new("#{File.basename(argv[0])} (code #{code}) : #{err.strip[0, 500]? || ""}") unless code == 0
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
      argv = [config.provision, "--manage", config.manage, "--domain", domain, "--database", database,
              "--pg-socket", config.pg_socket, "--output-dir", instances_dir] + company_options(params) + module_options(params)
      argv += ["--acme-email", config.acme_email] unless config.acme_email.empty?
      argv << "--acme-staging" if config.acme_staging
      argv << "--skip-createdb" if skip_createdb
      argv << slug
      Dir.mkdir_p(instances_dir)
      run!(argv, pg_env)
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      guard_database!(database)
      argv = [config.provision, "--files-only", "--manage", config.manage, "--domain", domain, "--database", database,
              "--pg-socket", config.pg_socket, "--output-dir", instances_dir] + module_options(params)
      argv += ["--locale", locale(params), slug]
      Dir.mkdir_p(instances_dir)
      run!(argv, pg_env)
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

    def manage_for(version : String?) : Array(String)
      if version && !version.empty?
        candidate = File.join(config.releases_dir, version, "bin", "partiduo-manage")
        return [candidate] if File.exists?(candidate)
      end
      config.manage.split(' ', remove_empty: true)
    end

    def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                 database : String? = nil) : InstanceReply
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
      argv = manage_for(version || current_release(slug)) + ["instance", action] + args
      code, output, errors = run(argv, env)
      InstanceReply.new(code, JSON.parse(reply_line(output, errors)))
    end

    # Dernière ligne JSON de la sortie ; à défaut, une erreur qui porte le
    # début de la sortie d'erreur (diagnostic dans le journal de la tâche).
    def reply_line(output : String, errors : String) : String
      output.lines.reverse!.find(&.starts_with?('{')) ||
        {"ok" => false, "error" => {"code" => "internal", "message" => "réponse illisible : #{errors.strip[0, 300]?}"}}.to_json
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

    def switch_release(slug : String, version : String) : Nil
      Dir.mkdir_p(instance_dir(slug))
      log("mode local : version #{version} pour #{slug}")
      File.write(File.join(instance_dir(slug), "RELEASE"), version)
    end

    def current_release(slug : String) : String?
      file = File.join(instance_dir(slug), "RELEASE")
      File.exists?(file) ? File.read(file).strip : nil
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
      File.write(guard_backup_path!(destination), lines.reject(&.empty?).uniq!.sort!.join { |line| "#{line}\n" })
      sources.each { |source| File.delete(source) if File.exists?(source) }
    end

    def tar_list?(path : String) : Bool
      code, _, _ = run(["tar", "-tzf", path])
      code == 0
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
  #   `pg_dump`, `pg_restore`), version, pièces jointes.
  #
  # Les bases et leurs objets appartiennent ainsi au rôle de l'instance
  # (`partiduo`), celui qui les fait tourner (D-AFN-005). L'exécutant ne
  # passe que des valeurs : sous-domaine, nom de base, version, chemins sous
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
      argv = ["provision", slug] + company_options(params) + module_options(params) + release_option(params)
      argv << "--skip-createdb" if skip_createdb
      run!(as_instance(argv))
    end

    def provision_files(slug : String, domain : String, params : JSON::Any, database : String) : String
      guard_slug!(slug)
      raise StepError.new("base refusée : #{database}", "usage") unless database == database_for(slug)
      run!(as_instance(["provision", slug, "--files-only", "--locale", locale(params)] + module_options(params) +
                       release_option(params)))
    end

    private def release_option(params : JSON::Any) : Array(String)
      version = params["version"]?.try(&.as_s?) || ""
      PartiduoAdmin::Protocol.valid_version?(version) ? ["--release", version] : [] of String
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

    def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                 database : String? = nil) : InstanceReply
      guard_slug!(slug)
      guard_database!(database) if database
      if version && !PartiduoAdmin::Protocol.valid_version?(version)
        raise StepError.new("version invalide : #{version}", "usage")
      end
      argv = as_instance(["cli", slug, database || "-", version || "-", action] + args)
      code, output, errors = run(argv)
      InstanceReply.new(code, JSON.parse(reply_line(output, errors)))
    end

    def service(slug : String, command : String) : String
      guard_slug!(slug)
      run!(as_root(["service", slug, command])) unless command == "status"
      code, _, _ = run(["systemctl", "is-active", "--quiet", "partiduo-#{slug}.service"], quiet: true)
      code == 0 ? "running" : "stopped"
    end

    def switch_release(slug : String, version : String) : Nil
      guard_slug!(slug)
      run!(as_instance(["release", slug, version]))
    end

    def current_release(slug : String) : String?
      File.basename(File.readlink(File.join(config.install_root, "instances", slug, "release")))
    rescue File::Error
      nil
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
