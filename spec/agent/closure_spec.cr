# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Clôture du lot A (relecture) : privilèges du mode production (enveloppes
# de sudo, argv produits), paramètres de tâche recalculés depuis le
# sous-domaine, paquet et restaurations, supervision robuste.

private APP_ROOT = File.expand_path("../..", __DIR__)

# Production enregistrée : aucune commande lancée, chaque argv retenu.
private class RecordingProduction < PartiduoAgent::ProductionSystem
  getter argvs = [] of Array(String)

  def run(argv : Array(String), env = {} of String => String, chdir : String? = nil, quiet : Bool = false) : {Int32, String, String}
    argvs << argv
    {0, %({"ok":true,"data":{"version":"0.1.0","contract":"1.0.0"}}), ""}
  end
end

private def production(domain = "partiduo.app") : RecordingProduction
  config = PartiduoAgent::Config.new
  config.mode = PartiduoAgent::Mode::Production
  config.domain = domain
  RecordingProduction.new(config, ->(_line : String) { nil })
end

private def params(slug = "garde", **extra) : Hash(String, JSON::Any)
  base = JSON.parse({"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost",
                     "database" => "", "modules" => ["accounting", "invoicing"], "extensions" => [] of String,
                     "package" => "app"}.to_json).as_h
  extra.each { |key, value| base[key.to_s] = JSON.parse(value.to_json) }
  base
end

private def run_dry(admin : AdminSpec::FakeAdmin, id : Int64, kind : String, task_params : Hash,
                    config = admin.config, databases = [] of String) : {JSON::Any, PartiduoAgent::DrySystem}
  admin.push(id, kind, task_params)
  runner = PartiduoAgent::Runner.new(config)
  dry = runner.build_system(->(_line : String) { nil }).as(PartiduoAgent::DrySystem)
  databases.each { |database| dry.databases << database; dry.provisioned << database }
  runner.run_once.should be_true
  {admin.finished[id], dry}
end

private def with_admin(&)
  admin = AdminSpec::FakeAdmin.new
  begin
    yield admin
  ensure
    admin.close
  end
end

# Enveloppe lancée hors sudo, avec la configuration d'essai `conf` ;
# `FAKE_ROOT` : répertoire des doublures (rc.conf, appels, services).
private def helper(name : String, conf : String, args : Array(String)) : {Int32, String, String}
  stdout = IO::Memory.new
  stderr = IO::Memory.new
  env = {"PARTIDUO_AGENT_HELPERS_CONF" => conf, "SUDO_USER" => nil, "FAKE_ROOT" => File.dirname(conf)} of String => String?
  status = Process.run(File.join(APP_ROOT, "deploy", "libexec", name), args, env: env, output: stdout, error: stderr)
  {status.exit_code, stdout.to_s, stderr.to_s}
end

describe "partiduo-agent : mode production (D-AFN-002, D-AFN-005)" do
  it "refuse une base qui n'est pas un nom sûr avant tout appel, et passe la base en argument, jamais dans un script" do
    system = production
    ["partiduo_x; touch /tmp/piege #", "partiduo_x y", "partiduo_admin", "postgres"].each do |database|
      expect_raises(PartiduoAgent::StepError) { system.instance("garde", "status", [] of String, nil, database) }
    end
    system.argvs.should be_empty

    system.instance("garde", "status", ["--task", "1"], nil, "partiduo_rt_garde_5")
    system.argvs.last.should eq(["/usr/local/bin/sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance",
                                 "cli", "garde", "partiduo_rt_garde_5", "-", "status", "--task", "1"])
    system.argvs.flatten.none? { |arg| arg == "sh" || arg == "-c" || arg.includes?("DATABASE_URL") }.should be_true

    expect_raises(PartiduoAgent::StepError, /paquet invalide/) { system.instance("garde", "status", [] of String, "../../x") }
    expect_raises(PartiduoAgent::StepError, /paquet invalide/) { system.instance("garde", "status", [] of String, "0.2.0") }
    # Instance pas encore déclarée : le paquet est passé à l'enveloppe.
    system.instance("garde", "version", ["--task", "2"], "devel")
    system.argvs.last.should eq(["/usr/local/bin/sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance",
                                 "cli", "garde", "-", "devel", "version", "--task", "2"])
    expect_raises(PartiduoAgent::StepError, /sous-domaine/) { system.instance("garde;x", "status", [] of String) }
  end

  it "fait créer, provisionner, sauvegarder et restaurer les bases sous le compte des instances" do
    system = production
    instance_helper = ["/usr/local/bin/sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance"]
    create = JSON.parse(params.merge({"name" => "Garde SAS", "regime" => "fr", "locale" => "fr", "admin_email" => "a@b.fr",
                                      "siren" => "", "vat" => ""}).to_json)
    system.provision("garde", "partiduo.app", create, "partiduo_garde", skip_createdb: false)
    argv = system.argvs.last
    argv[0, 7].should eq(instance_helper + ["provision", "garde"])
    argv.should contain("--name")
    argv.should contain("Garde SAS")
    argv.each_cons_pair.to_a.should contain({"--package", "app"})
    argv.should_not contain("--release")
    # Rôle propriétaire, racines, socket et gabarits : fixés par l'enveloppe.
    %w[--manage --owner --output-dir --install-root --etc-dir --data-dir --database --version].each do |option|
      argv.any?(&.starts_with?(option)).should be_false
    end
    expect_raises(PartiduoAgent::StepError, /base refusée/) do
      system.provision("garde", "partiduo.app", create, "partiduo_autre", skip_createdb: false)
    end

    system.createdb("partiduo_garde")
    system.argvs.last.should eq(instance_helper + ["createdb", "partiduo_garde"])
    system.dropdb("partiduo_garde")
    system.argvs.last.should eq(instance_helper + ["dropdb", "partiduo_garde"])
    dump = File.join(system.backup_root("garde"), "b.dump")
    system.pg_dump("partiduo_garde", dump)
    system.argvs.last.should eq(instance_helper + ["dump", "partiduo_garde", dump])
    system.pg_restore("partiduo_garde", dump)
    system.argvs.last.should eq(instance_helper + ["restore", "partiduo_garde", dump])
    expect_raises(PartiduoAgent::StepError, /hors du répertoire/) { system.pg_dump("partiduo_garde", "/etc/x.dump") }
    system.mkdir(system.backup_root("garde"))
    system.argvs.last.should eq(instance_helper + ["backup-dir", "garde"])
    expect_raises(PartiduoAgent::StepError, /refusé/) { system.mkdir("/etc") }
    # Paquet de l'instance neuve d'une restauration ; valeur libre refusée.
    system.provision_files("garde", "partiduo.app", JSON.parse(params(package: "devel").to_json), "partiduo_garde")
    system.argvs.last.each_cons_pair.to_a.should contain({"--package", "devel"})
    expect_raises(PartiduoAgent::StepError, /paquet invalide/) do
      system.provision("garde", "partiduo.app", JSON.parse(params(package: "../x").to_json), "partiduo_garde", skip_createdb: false)
    end
    system.argvs.flatten.none?(&.==("release")).should be_true
  end

  it "ne passe à root que des sous-domaines, par l'enveloppe racine" do
    system = production
    root_helper = ["/usr/local/bin/sudo", "-n", "/usr/local/libexec/partiduo-agent/partiduo-agent-root"]
    system.service("garde", "stop").should eq("running")
    system.argvs[-2].should eq(root_helper + ["service", "garde", "stop"])
    # État : code de sortie de `service … status`, par la même enveloppe.
    system.argvs.last.should eq(root_helper + ["service", "garde", "status"])
    system.service("garde", "status")
    system.argvs.last.should eq(root_helper + ["service", "garde", "status"])
    system.argvs.flatten.none?(&.includes?("systemctl")).should be_true
    expect_raises(PartiduoAgent::StepError, /commande refusée/) { system.service("garde", "restart") }
    system.install_instance("garde", "garde.partiduo.app", "devel")
    system.argvs.should contain(root_helper + ["install", "garde", "devel"])
    expect_raises(PartiduoAgent::StepError, /paquet invalide/) { system.install_instance("garde", "garde.partiduo.app", "../x") }
    system.remove_instance("garde", "garde.partiduo.app")
    system.argvs.last.should eq(root_helper + ["remove", "garde"])
    system.argvs.flatten.none?(&.includes?("INSTALL.txt")).should be_true
    expect_raises(PartiduoAgent::StepError) { system.service("garde x", "stop") }
  end

  it "exige un domaine en production" do
    config = PartiduoAgent::Config.new
    config.token = "x"
    config.admin_url = "https://admin.partiduo.app"
    config.mode = PartiduoAgent::Mode::Production
    expect_raises(ArgumentError, /--domain/) { config.validate! }
    config.domain = "partiduo app"
    expect_raises(ArgumentError, /domaine invalide/) { config.validate! }
    config.domain = "partiduo.app"
    config.validate!
  end
end

describe "partiduo-agent : paramètres recalculés depuis le sous-domaine (D-AFN-004)" do
  it "refuse l'hôte, la base ou le domaine d'un autre dossier" do
    with_admin do |admin|
      report, dry = run_dry(admin, 60_i64, "instance.delete", params(host: "autre.partiduo.localhost"))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("hôte refusé")
      dry.calls.should be_empty

      report, dry = run_dry(admin, 61_i64, "instance.delete", params(database: "partiduo_adm_autre"))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("base refusée")
      dry.calls.none?(&.starts_with?("dropdb")).should be_true

      config = admin.config
      report, _ = run_dry(admin, 62_i64, "backup.restore",
        params(path: File.join(config.backup_dir, "garde", "b.dump"), target: "replace", database: "partiduo_adm_voisin"), config)
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("base refusée")

      config = admin.config
      config.domain = "partiduo.app"
      report, _ = run_dry(admin, 63_i64, "instance.suspend", params, config)
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("domaine refusé")
    end
  end
end

describe "partiduo-agent : paquet et restaurations" do
  it "refuse une tâche dont le paquet n'est ni app ni devel, avant tout geste" do
    with_admin do |admin|
      report, dry = run_dry(admin, 70_i64, "instance.create", params(package: "../../tmp/piege"))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("paquet invalide")
      dry.calls.should be_empty
    end
  end

  it "rend avec une sauvegarde la version que rend l'instance" do
    with_admin do |admin|
      report, dry = run_dry(admin, 71_i64, "backup.run", params(kind: "manual"), databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      # Version de la sauvegarde : celle que rend l'instance, sans lien de version.
      report["result"]["version"].should eq(dry.version)
      dry.calls.none?(&.starts_with?("release")).should be_true
    end
  end

  it "relève les pièces jointes avant et après pg_dump et archive leur union (D-AFN-012)" do
    with_admin do |admin|
      report, dry = run_dry(admin, 72_i64, "backup.run", params(kind: "manual"), databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      plans = dry.calls.each_index.select { |index| dry.calls[index].starts_with?("instance backup-plan") }.to_a
      plans.size.should eq(2)
      dump = dry.calls.index!(&.starts_with?("pg_dump"))
      plans.first.should be < dump
      plans.last.should be > dump
      dry.calls.index!(&.starts_with?("listes")).should be < dry.calls.index!(&.starts_with?("tar "))
    end
  end

  it "installe une restauration en instance neuve comme une création (D-AFN-009)" do
    with_admin do |admin|
      config = admin.config
      path = File.join(config.backup_dir, "garde", "b.dump")
      media = File.join(config.backup_dir, "garde", "b.media.tar.gz")
      task_params = params(path: path, media_path: media, target: "new", new_slug: "copie", new_host: "copie.partiduo.localhost")
      report, dry = run_dry(admin, 73_i64, "backup.restore", task_params, config)
      report["ok"].as_bool.should be_true
      dry.calls.should contain("partiduo-provision --files-only copie partiduo_adm_copie app")
      dry.packages["copie"].should eq("app")
      dry.calls.should contain("install copie.partiduo.localhost")
      dry.calls.should contain("tar -x #{media} copie")
      report["result"]["database"].should eq("partiduo_adm_copie")
      report["result"]["certificate"]["issued"].as_bool.should be_false

      report, _ = run_dry(admin, 74_i64, "backup.restore", task_params.merge({"new_host" => "copie.ailleurs.example"}), config)
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("hôte refusé")
    end
  end

  it "arrête le service avant la sauvegarde de sûreté d'un remplacement" do
    with_admin do |admin|
      config = admin.config
      path = File.join(config.backup_dir, "garde", "b.dump")
      report, dry = run_dry(admin, 75_i64, "backup.restore", params(path: path, target: "replace"), config,
        databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      dry.calls.index!("service stop garde").should be < dry.calls.index!(&.starts_with?("pg_dump"))
      dry.calls.index!(&.starts_with?("pg_dump")).should be < dry.calls.index!("dropdb partiduo_adm_garde")
    end
  end
end

describe "partiduo-agent : supervision (D-AFN-015)" do
  it "ignore une entrée mal formée ou étrangère sans faire échouer les autres" do
    with_admin do |admin|
      dossiers = [JSON.parse(%({"slug":5})), JSON::Any.new("texte"), JSON.parse(%({"host":"x"})),
                  JSON.parse(%({"slug":"garde","host":"garde.partiduo.localhost","database":"partiduo_adm_garde"})),
                  JSON.parse(%({"slug":"vole","host":"vole.partiduo.localhost","database":"partiduo_adm_garde"}))]
      report, _ = run_dry(admin, 80_i64, "supervision.check", {"dossiers" => dossiers, "domain" => "partiduo.localhost"},
        databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      entries = report["result"]["dossiers"].as_a
      entries.map(&.["slug"].as_s).should eq(["garde"])
      entries.first["database"].should eq("ok")
      admin.logs[80_i64].join("\n").should contain("vole ignoré")
    end
  end
end

describe "partiduo-agent : ordre des pièces (D-AFN-006)" do
  it "active les pièces requises d'abord et désactive les dépendantes d'abord" do
    depends = PartiduoAgent::Plans.dependencies(JSON.parse(<<-JSON))
      {"modules":[{"code":"INVOICING","depends_on":[]},{"code":"EINVOICING","depends_on":["INVOICING"]},
                  {"code":"STOCK","depends_on":["ACCOUNTING|INVOICING"]},{"code":"ACCOUNTING","depends_on":[]}]}
      JSON
    PartiduoAgent::Plans.enable_order(%w[einvoicing stock invoicing], depends).should eq(%w[invoicing einvoicing stock])
    PartiduoAgent::Plans.disable_order(%w[invoicing einvoicing accounting], depends).should eq(%w[einvoicing invoicing accounting])
    PartiduoAgent::Plans.disable_order(%w[a b], PartiduoAgent::Plans::Depends.new).should eq(%w[a b])
  end
end

# Doublures des outils de FreeBSD (sysrc, service, certbot, nginx, install
# sans changement de propriétaire, pg_dump en échec) : rc.conf, appels et
# services tenus dans $FAKE_ROOT.
private HELPER_DOUBLES = {
  "sysrc" => <<-'SH',
    #!/bin/sh
    f="$FAKE_ROOT/rc.conf"
    touch "$f"
    get() { sed -n "s/^$1=\"\(.*\)\"\$/\1/p" "$f" | tail -n 1; }
    put() { grep -v "^$1=" "$f" > "$f.new" || true; printf '%s="%s"\n' "$1" "$2" >> "$f.new"; mv "$f.new" "$f"; }
    case "$1" in
      -n) grep -q "^$2=" "$f" || exit 1; get "$2" ;;
      *+=*) put "${1%%+=*}" "$(echo $(get "${1%%+=*}") ${1#*+=})" ;;
      *-=*) name="${1%%-=*}"; kept=""; for word in $(get "$name"); do [ "$word" = "${1#*-=}" ] || kept="$kept $word"; done
            put "$name" "$(echo $kept)" ;;
      *=*) put "${1%%=*}" "${1#*=}" ;;
    esac
    SH
  "service" => <<-SH,
    #!/bin/sh
    echo "service $*" >> "$FAKE_ROOT/calls"
    [ "$1" = nginx ] && exit 0
    case "$2" in
      start) touch "$FAKE_ROOT/running.$1.$3" ;;
      stop) rm -f "$FAKE_ROOT/running.$1.$3" ;;
      status) test -f "$FAKE_ROOT/running.$1.$3" ;;
    esac
    SH
  "certbot" => "#!/bin/sh\necho \"certbot $*\" >> \"$FAKE_ROOT/calls\"\n",
  "nginx"   => "#!/bin/sh\necho \"nginx $*\" >> \"$FAKE_ROOT/calls\"\n",
  "pg_dump" => "#!/bin/sh\necho 'pg_dump: error: connection to server failed' >&2\nexit 1\n",
  "install" => <<-SH,
    #!/bin/sh
    n=$#; i=0
    while [ $i -lt $n ]; do
      a=$1; shift; i=$((i + 1))
      case $a in -o | -g) shift; i=$((i + 1)) ;; *) set -- "$@" "$a" ;; esac
    done
    exec /usr/bin/install "$@"
    SH
}

private def helper_bench(dir : String) : String
  bin = File.join(dir, "bin")
  Dir.mkdir_p(bin)
  HELPER_DOUBLES.each { |name, script| File.write(File.join(bin, name), script, perm: 0o755) }
  root = File.join(dir, "root")
  {"partiduo", "partiduo-devel"}.each do |package|
    home = File.join(root, "usr", "local", "lib", package)
    Dir.mkdir_p(File.join(home, "bin"))
    Dir.mkdir_p(File.join(home, "deploy", "templates"))
    File.write(File.join(home, "bin", "partiduo-manage"), "#!/bin/sh\nprintf '%s\\n' \"#{package}\" \"DB=$DATABASE_URL\" \"$@\"\n", perm: 0o755)
    templates = File.join(home, "deploy", "templates")
    File.write(File.join(templates, "nginx-acme.conf.tmpl"), "server { server_name {{HOST}}; root {{ACME_WEBROOT}}; }\n")
    File.write(File.join(templates, "nginx-vhost.conf.tmpl"),
      "server { server_name {{HOST}}; ssl_certificate /usr/local/etc/letsencrypt/live/{{HOST}}/fullchain.pem; " \
      "proxy_pass http://127.0.0.1:{{PORT}}; }\n")
    File.write(File.join(templates, "partiduo-instance.cron.tmpl"),
      "{{DAILY_MINUTE}} 3 * * * {{SYSTEM_USER}} . {{ENV_FILE}} && cd {{DATA_DIR}}/{{DOSSIER}} && {{MANAGE_PATH}} {{DAILY_COMMAND}}\n")
  end
  Dir.mkdir_p(File.join(root, "usr", "local", "etc", "nginx"))
  File.write(File.join(root, "usr", "local", "etc", "nginx", "nginx.conf"), "http {\n  include partiduo/*.conf;\n}\n")
  Dir.mkdir_p(File.join(dir, "backups"))
  File.write(File.join(dir, "rc.conf"), %(partiduo_devel_instances="demo"\n))
  conf = File.join(dir, "helpers.conf")
  File.write(conf, <<-CONF)
    DOMAIN=partiduo.test
    ETC_DIR=#{dir}/etc
    DATA_DIR=#{dir}/data
    BACKUP_DIR=#{dir}/backups
    STAGE_DIR=#{dir}/stage
    ACME_WEBROOT=#{dir}/acme
    PG_SOCKET=/tmp
    SYSTEM_ROOT=#{root}
    SYSRC=#{bin}/sysrc
    SERVICE=#{bin}/service
    CERTBOT=#{bin}/certbot
    NGINX=#{bin}/nginx
    INSTALL=#{bin}/install
    PG_DUMP=#{bin}/pg_dump
    CONF
  conf
end

private def instance_env(dir : String, slug : String, port = 8163, **extra) : Nil
  Dir.mkdir_p(File.join(dir, "stage", slug))
  lines = ["MARTEN_ENV=production", "MARTEN_SECRET_KEY=#{"a" * 64}", "MARTEN_ALLOWED_HOSTS=#{slug}.partiduo.test",
           "DATABASE_URL=postgres:///partiduo_#{slug}?host=/tmp", "PARTIDUO_MODULES=accounting,invoicing",
           "PARTIDUO_DOMAIN=partiduo.test", "PARTIDUO_MEDIA_ROOT=#{dir}/data/#{slug}/media", "PARTIDUO_MODELES_PDF=auto",
           "PORT=#{port}"]
  extra.each { |key, value| lines << "#{key}=#{value}" }
  File.write(File.join(dir, "stage", slug, "#{slug}.env"), lines.join("\n") + "\n")
end

describe "partiduo-agent : scripts enveloppes de sudo (D-AFN-002)" do
  it "valident chaque argument avant tout geste" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    conf = helper_bench(dir)
    piege = File.join(dir, "piege")

    [
      ["cli", "demo", "partiduo_x;touch #{piege}", "-", "status"],
      ["cli", "demo", "partiduo_x $(touch #{piege})", "-", "status"],
      ["cli", "demo;touch #{piege}", "-", "-", "status"],
      ["cli", "admin", "-", "-", "status"],
      ["cli", "demo", "-", "-", "shell"],
      ["cli", "demo", "-", "../../x", "status"],
      ["cli", "demo", "-", "-", "backup-plan", "--list-file", "/etc/passwd"],
      ["cli", "demo", "-", "-", "backup-plan", "--list-file=#{dir}/backups/../x"],
      ["provision", "demo", "--package", "devel", "--manage", "/bin/sh"],
      ["provision", "demo", "--package", "devel", "--release", "1.0.0"],
      ["provision", "demo", "--package", "../x"],
      ["provision", "demo", "--regime", "fr"],
      ["provision", "demo", "--package", "devel", "--regime", "xx"],
      ["dump", "partiduo_demo", "/etc/x.dump"],
      ["createdb", "partiduo_admin"],
      ["release", "demo", "1.0.0"],
      ["frob"],
    ].each do |args|
      code, _, errors = helper("partiduo-agent-instance", conf, args)
      code.should eq(2)
      errors.should start_with("partiduo-agent-instance : ")
    end

    instance_env(dir, "demo", LD_PRELOAD: "/tmp/x.so")
    [
      ["install", "demo", "devel"],
      ["install", "demo"],
      ["install", "demo x", "app"],
      ["install", "demo", "prod"],
      ["service", "demo x", "start"],
      ["service", "demo", "restart"],
      ["cert", "demo.ailleurs.example", "exists"],
      ["cert", "admin.partiduo.test", "exists"],
      ["remove", "../etc"],
    ].each do |args|
      code, _, errors = helper("partiduo-agent-root", conf, args)
      code.should eq(2)
      errors.should start_with("partiduo-agent-root : ")
    end
    # Fichier d'environnement : base d'un autre dossier refusée, valeur jamais répétée.
    instance_env(dir, "demo", DATABASE_URL: "postgres:///partiduo_voisin?host=/tmp")
    _, _, errors = helper("partiduo-agent-root", conf, ["install", "demo", "-"])
    errors.should contain("DATABASE_URL refusée")
    errors.should_not contain("partiduo_voisin")
    # Fichiers statiques : ceux du paquet, jamais détournés par l'environnement.
    instance_env(dir, "demo", PARTIDUO_ASSETS_ROOT: "/tmp/assets")
    _, _, errors = helper("partiduo-agent-root", conf, ["install", "demo", "-"])
    errors.should contain("clé refusée : PARTIDUO_ASSETS_ROOT")
    Dir.exists?(File.join(dir, "etc")).should be_false
    File.exists?(piege).should be_false
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  it "prennent le paquet déclaré dans rc.conf, refusent un paquet contraire ou une double déclaration" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    conf = helper_bench(dir)

    code, output, _ = helper("partiduo-agent-instance", conf, ["cli", "demo", "partiduo_rt_demo_5", "-", "status", "--task", "1"])
    code.should eq(0)
    output.lines.should eq(["partiduo-devel", "DB=postgres:///partiduo_rt_demo_5?host=/tmp", "instance", "status", "--task", "1"])
    helper("partiduo-agent-instance", conf, ["cli", "demo", "-", "devel", "version"])[0].should eq(0)
    code, _, errors = helper("partiduo-agent-instance", conf, ["cli", "demo", "-", "app", "version"])
    code.should eq(2)
    errors.should contain("contraire à la déclaration")
    # Instance pas encore déclarée : le paquet explicite seulement.
    helper("partiduo-agent-instance", conf, ["cli", "neuve", "-", "-", "status"])[2].should contain("non déclarée")
    helper("partiduo-agent-instance", conf, ["cli", "neuve", "-", "app", "status"])[1].lines.first.should eq("partiduo")

    File.write(File.join(dir, "rc.conf"), %(partiduo_instances="demo"\npartiduo_devel_instances="autre demo"\n))
    code, _, errors = helper("partiduo-agent-instance", conf, ["cli", "demo", "-", "-", "status"])
    code.should eq(2)
    errors.should contain("déclarée dans les deux paquets")
    helper("partiduo-agent-root", conf, ["service", "demo", "status"])[0].should eq(2)
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  it "installent, servent et retirent une instance comme l'INSTALL.txt de partiduo-provision" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    conf = helper_bench(dir)
    root = File.join(dir, "root")
    instance_env(dir, "neuve", 8163)

    code, _, errors = helper("partiduo-agent-root", conf, ["install", "neuve", "app"])
    errors.should eq("")
    code.should eq(0)
    rc_conf = File.read(File.join(dir, "rc.conf"))
    rc_conf.should contain(%(partiduo_instances="neuve"))
    rc_conf.should contain(%(partiduo_enable="YES"))
    File.read(File.join(dir, "etc", "neuve.env")).should contain("PARTIDUO_MEDIA_ROOT=#{dir}/data/neuve/media")
    Dir.exists?(File.join(dir, "data", "neuve", "media")).should be_true
    Dir.exists?(File.join(root, "var", "log", "partiduo")).should be_true
    File.read(File.join(root, "usr", "local", "etc", "cron.d", "partiduo-neuve")).should eq(
      "3 3 * * * partiduo . #{dir}/etc/neuve.env && cd #{dir}/data/neuve && " \
      "#{root}/usr/local/lib/partiduo/bin/partiduo-manage invoicing_month_end\n")
    File.read(File.join(root, "usr", "local", "etc", "nginx", "partiduo", "neuve.conf")).should contain("127.0.0.1:8163")
    calls = File.read_lines(File.join(dir, "calls"))
    calls.should contain("service partiduo start neuve")
    calls.last.should eq("service nginx reload")
    certbot = calls.find!(&.starts_with?("certbot certonly"))
    certbot.should contain("--cert-name neuve.partiduo.test")
    certbot.should end_with("--deploy-hook service nginx reload")

    # Rejouée : ni doublon dans rc.conf, ni redémarrage.
    helper("partiduo-agent-root", conf, ["install", "neuve", "-"])[0].should eq(0)
    File.read(File.join(dir, "rc.conf")).should contain(%(partiduo_instances="neuve"\n))
    File.read_lines(File.join(dir, "calls")).count("service partiduo start neuve").should eq(1)

    helper("partiduo-agent-root", conf, ["service", "neuve", "status"])[0].should eq(0)
    helper("partiduo-agent-root", conf, ["service", "neuve", "stop"])[0].should eq(0)
    helper("partiduo-agent-root", conf, ["service", "neuve", "status"])[0].should_not eq(0)

    helper("partiduo-agent-root", conf, ["remove", "neuve"])[0].should eq(0)
    File.read(File.join(dir, "rc.conf")).should_not contain("neuve")
    [File.join(root, "usr", "local", "etc", "cron.d", "partiduo-neuve"), File.join(root, "usr", "local", "etc", "nginx", "partiduo", "neuve.conf"),
     File.join(dir, "etc", "neuve.env"), File.join(dir, "data", "neuve"), File.join(dir, "stage", "neuve")].each do |path|
      File.exists?(path).should be_false
    end
    File.read_lines(File.join(dir, "calls")).should contain("certbot delete --cert-name neuve.partiduo.test --non-interactive")
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  it "archivent les seules pièces encore présentes (bsdtar) et ne masquent pas un échec de pg_dump" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    conf = helper_bench(dir)
    media = File.join(dir, "data", "demo", "media", "attachments")
    Dir.mkdir_p(media)
    File.write(File.join(media, "a.pdf"), "a")
    File.write(File.join(media, "c d.pdf"), "c")
    helper("partiduo-agent-instance", conf, ["backup-dir", "demo"])[0].should eq(0)
    list = File.join(dir, "backups", "demo", "b.files")
    File.write(list, "attachments/a.pdf\nattachments/effacee.pdf\nattachments/c d.pdf\n")
    archive = File.join(dir, "backups", "demo", "b.media.tar.gz")

    code, _, errors = helper("partiduo-agent-instance", conf, ["media-archive", "demo", list, archive])
    errors.should eq("")
    code.should eq(0)
    listing = IO::Memory.new
    Process.run("tar", ["-tzf", archive], output: listing).success?.should be_true
    listing.to_s.lines.should eq(["attachments/a.pdf", "attachments/c d.pdf"])

    code, _, errors = helper("partiduo-agent-instance", conf, ["dump", "partiduo_demo", "-"])
    code.should_not eq(0)
    errors.should contain("pg_dump: error")
  ensure
    FileUtils.rm_rf(dir) if dir
  end
end
