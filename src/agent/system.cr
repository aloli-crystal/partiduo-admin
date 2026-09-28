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
    abstract def provision(slug : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
    abstract def install_instance(slug : String, host : String) : Bool
    abstract def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                          database : String? = nil) : InstanceReply
    abstract def service(slug : String, command : String) : String
    abstract def switch_release(slug : String, version : String) : Nil
    abstract def current_release(slug : String) : String?
    abstract def pg_dump(database : String, path : String) : Nil
    abstract def pg_restore(database : String, path : String) : Nil
    abstract def pg_restore_list?(path : String) : Bool
    abstract def tar_create(root : String, list_file : String, path : String) : Nil
    abstract def tar_extract(path : String, root : String) : Nil
    abstract def tar_list?(path : String) : Bool
    abstract def sha256(path : String) : String
    abstract def size(path : String) : Int64
    abstract def exists?(path : String) : Bool
    abstract def remove(path : String) : Nil
    abstract def mkdir(path : String) : Nil
    abstract def disk(path : String) : {Int64, Int64}
    abstract def cert_expiry(host : String) : Time?
    abstract def remove_instance(slug : String, host : String) : Nil
    abstract def render_instance(slug : String, host : String, database : String, params : JSON::Any) : Nil

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

    def provision(slug : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
      op("partiduo-provision", "#{slug} #{database}")
      databases << database
      provisioned << database
      releases[slug] = params["version"]?.try(&.as_s?).presence || "0.1.0"
      "== Instance #{slug} provisionnée.\nInvitation : https://#{params["host"]?.try(&.as_s?)}/invitation/DRYRUNTOKEN\n"
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
         "read_only" => {"active" => read_only.includes?(db)}, "migrations" => {"applied" => 10, "pending" => 0}}
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

    def tar_create(root : String, list_file : String, path : String) : Nil
      op("tar", path)
      files[path] = 512_i64
    end

    def tar_extract(path : String, root : String) : Nil
      op("tar -x", "#{path} #{root}")
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

    def remove(path : String) : Nil
      op("rm", path)
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

    def render_instance(slug : String, host : String, database : String, params : JSON::Any) : Nil
      op("fichiers de service", host)
    end
  end

  # Mode local : vraies bases `partiduo_adm_*` et vrais outils PostgreSQL,
  # sans vhost, systemd ni Let's Encrypt — les fichiers de service sont
  # produits dans `work_dir`, et l'arrêt d'un service est un fichier témoin.
  class LocalSystem < System
    DATABASE = /\A[a-z_][a-z0-9_]{0,62}\z/

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

    def provision(slug : String, params : JSON::Any, database : String, skip_createdb : Bool) : String
      guard_database!(database)
      argv = [config.provision, "--manage", config.manage, "--name", params["name"].as_s, "--regime", params["regime"].as_s,
              "--locale", params["locale"]?.try(&.as_s?).presence || "fr",
              "--admin-email", params["admin_email"].as_s,
              "--modules", params["modules"].as_a.map(&.as_s).join(','),
              "--domain", params["domain"].as_s, "--database", database, "--pg-socket", config.pg_socket,
              "--output-dir", instances_dir]
      extensions = params["extensions"]?.try(&.as_a.map(&.as_s)) || [] of String
      argv += ["--with", extensions.join(',')] unless extensions.empty?
      if siren = params["siren"]?.try(&.as_s?).presence
        argv += ["--siren", siren]
      end
      if vat = params["vat"]?.try(&.as_s?).presence
        argv += ["--vat", vat]
      end
      argv += ["--acme-email", config.acme_email] unless config.acme_email.empty?
      argv << "--acme-staging" if config.acme_staging
      argv << "--skip-createdb" if skip_createdb
      argv << slug
      Dir.mkdir_p(instances_dir)
      run!(argv, pg_env)
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

    def tar_create(root : String, list_file : String, path : String) : Nil
      Dir.mkdir_p(File.dirname(path))
      if !Dir.exists?(root) || File.size(list_file).zero?
        # Aucune pièce jointe : archive vide, pour une sauvegarde homogène.
        run!(["tar", "-czf", path, "-T", "/dev/null"])
      else
        run!(["tar", "-C", root, "-czf", path, "-T", list_file])
      end
    end

    def tar_extract(path : String, root : String) : Nil
      Dir.mkdir_p(root)
      run!(["tar", "-C", root, "-xzf", path])
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

    def render_instance(slug : String, host : String, database : String, params : JSON::Any) : Nil
      guard_database!(database)
      Dir.mkdir_p(instance_dir(slug))
      source = instance_env(params["slug"].as_s)
      source["DATABASE_URL"] = "postgres:///#{database}?host=#{config.pg_socket}"
      source["PARTIDUO_HOST"] = host if source.has_key?("PARTIDUO_HOST")
      File.write(File.join(instance_dir(slug), "#{slug}.env"), source.map { |key, value| "#{key}=#{value}" }.join("\n") + "\n")
      log("mode local : fichier d'environnement de #{slug} produit dans #{instance_dir(slug)}")
    end
  end

  # Production : services systemd, vhosts nginx et certificats par
  # `sudo -n` (règles sudoers limitées, voir README), instance appelée sous
  # son compte système avec son fichier d'environnement.
  class ProductionSystem < LocalSystem
    def instances_dir : String
      File.join(config.state_dir, "instances")
    end

    def install_instance(slug : String, host : String) : Bool
      before = cert_exists?(host)
      run!(["sudo", "-n", "sh", "INSTALL.txt"], chdir: instance_dir(slug))
      !before && cert_exists?(host) && !config.acme_staging
    end

    def cert_exists?(host : String) : Bool
      code, _, _ = run(["sudo", "-n", "test", "-f", "/etc/letsencrypt/live/#{host}/fullchain.pem"], quiet: true)
      code == 0
    end

    def instance(slug : String, action : String, args : Array(String), version : String? = nil,
                 database : String? = nil) : InstanceReply
      release = File.join(config.install_root, "instances", slug, "release", "bin", "partiduo-manage")
      manage = version ? File.join(config.releases_dir, version, "bin", "partiduo-manage") : release
      override = database ? "DATABASE_URL=postgres:///#{database}?host=#{config.pg_socket} " : ""
      script = %(set -a && . "$1" && set +a && shift && exec env #{override}"$@")
      argv = ["sudo", "-n", "-u", config.system_user, "sh", "-c", script, "sh",
              File.join(config.etc_dir, "#{slug}.env"), manage, "instance", action] + args
      code, output, errors = run(argv)
      InstanceReply.new(code, JSON.parse(reply_line(output, errors)))
    end

    def service(slug : String, command : String) : String
      unit = "partiduo-#{slug}.service"
      run!(["sudo", "-n", "systemctl", command, unit]) unless command == "status"
      code, _, _ = run(["systemctl", "is-active", "--quiet", unit], quiet: true)
      code == 0 ? "running" : "stopped"
    end

    def switch_release(slug : String, version : String) : Nil
      run!(["sudo", "-n", "-u", config.system_user, "ln", "-sfn", File.join(config.releases_dir, version),
            File.join(config.install_root, "instances", slug, "release")])
    end

    def current_release(slug : String) : String?
      File.basename(File.readlink(File.join(config.install_root, "instances", slug, "release")))
    rescue File::Error
      nil
    end

    def cert_expiry(host : String) : Time?
      code, output, _ = run(["sudo", "-n", "openssl", "x509", "-enddate", "-noout", "-in",
                             "/etc/letsencrypt/live/#{host}/cert.pem"], quiet: true)
      return unless code == 0
      Time.parse(output.strip.sub("notAfter=", ""), "%b %e %H:%M:%S %Y %Z", Time::Location::UTC)
    rescue Time::Format::Error
      nil
    end

    def remove_instance(slug : String, host : String) : Nil
      unit = "partiduo-#{slug}"
      run(["sudo", "-n", "systemctl", "disable", "--now", "#{unit}.service"])
      run!(["sudo", "-n", "rm", "-f", "/etc/systemd/system/#{unit}.service", "/etc/nginx/sites-enabled/#{unit}.conf",
            "/etc/nginx/sites-available/#{unit}.conf", File.join(config.etc_dir, "#{slug}.env")])
      run(["sudo", "-n", "certbot", "delete", "--cert-name", host, "--non-interactive"])
      run!(["sudo", "-n", "systemctl", "daemon-reload"])
      run(["sudo", "-n", "systemctl", "reload", "nginx"])
    end

    # Instance neuve restaurée : fichier d'environnement dérivé de celui du
    # dossier source, installé par les mêmes gestes que partiduo-provision.
    def render_instance(slug : String, host : String, database : String, params : JSON::Any) : Nil
      Dir.mkdir_p(instance_dir(slug))
      _, source, _ = run(["sudo", "-n", "cat", File.join(config.etc_dir, "#{params["slug"].as_s}.env")], quiet: true)
      env = source.lines.map do |line|
        case line
        when .starts_with?("DATABASE_URL=") then "DATABASE_URL=postgres:///#{database}?host=#{config.pg_socket}"
        else                                     line.gsub(params["host"].as_s, host)
        end
      end
      File.write(File.join(instance_dir(slug), "#{slug}.env"), env.join("\n") + "\n", perm: 0o600)
      log("instance #{slug} : fichier d'environnement produit ; service, vhost et certificat à installer comme partiduo-provision")
    end
  end
end
