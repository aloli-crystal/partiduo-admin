# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Clôture du lot A (relecture) : privilèges du mode production (enveloppes
# de sudo, argv produits), paramètres de tâche recalculés depuis le
# sous-domaine, montée de version et restaurations, supervision robuste.

private APP_ROOT = File.expand_path("../..", __DIR__)

# Production enregistrée : aucune commande lancée, chaque argv retenu.
private class RecordingProduction < PartiduoAgent::ProductionSystem
  getter argvs = [] of Array(String)

  def run(argv : Array(String), env = {} of String => String, chdir : String? = nil, quiet : Bool = false) : {Int32, String, String}
    argvs << argv
    {0, %({"ok":true,"data":{"version":"0.1.0","contract":"1.0.0"}}), ""}
  end
end

# À blanc, mais une étape lève une exception qui n'est pas une `StepError`.
private class ExplodingSystem < PartiduoAgent::DrySystem
  @exploded = false

  def service(slug : String, command : String) : String
    if command == "start" && !@exploded
      @exploded = true
      raise KeyError.new("clé absente de la réponse")
    end
    super
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
                     "version" => "0.1.0"}.to_json).as_h
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

private def helper(name : String, conf : String, args : Array(String)) : {Int32, String, String}
  stdout = IO::Memory.new
  stderr = IO::Memory.new
  env = {"PARTIDUO_AGENT_HELPERS_CONF" => conf, "SUDO_USER" => nil} of String => String?
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
    system.argvs.last.should eq(["sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance",
                                 "cli", "garde", "partiduo_rt_garde_5", "-", "status", "--task", "1"])
    system.argvs.flatten.none? { |arg| arg == "sh" || arg == "-c" || arg.includes?("DATABASE_URL") }.should be_true

    expect_raises(PartiduoAgent::StepError, /version invalide/) { system.instance("garde", "status", [] of String, "../../x") }
    expect_raises(PartiduoAgent::StepError, /sous-domaine/) { system.instance("garde;x", "status", [] of String) }
  end

  it "fait créer, provisionner, sauvegarder et restaurer les bases sous le compte des instances" do
    system = production
    instance_helper = ["sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance"]
    create = JSON.parse(params.merge({"name" => "Garde SAS", "regime" => "fr", "locale" => "fr", "admin_email" => "a@b.fr",
                                      "siren" => "", "vat" => ""}).to_json)
    system.provision("garde", "partiduo.app", create, "partiduo_garde", skip_createdb: false)
    argv = system.argvs.last
    argv[0, 7].should eq(instance_helper + ["provision", "garde"])
    argv.should contain("--name")
    argv.should contain("Garde SAS")
    argv.should contain("--release")
    # Rôle propriétaire, racines, socket et gabarits : fixés par l'enveloppe.
    %w[--manage --owner --output-dir --install-root --etc-dir --database].each { |option| argv.should_not contain(option) }
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
    system.switch_release("garde", "0.2.0")
    system.argvs.last.should eq(instance_helper + ["release", "garde", "0.2.0"])
  end

  it "ne passe à root que des sous-domaines, par l'enveloppe racine" do
    system = production
    root_helper = ["sudo", "-n", "/usr/local/libexec/partiduo-agent/partiduo-agent-root"]
    system.service("garde", "stop")
    system.argvs[-2].should eq(root_helper + ["service", "garde", "stop"])
    system.argvs.last.should eq(["systemctl", "is-active", "--quiet", "partiduo-garde.service"])
    system.install_instance("garde", "garde.partiduo.app")
    system.argvs.should contain(root_helper + ["install", "garde"])
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

describe "partiduo-agent : montée de version et restaurations" do
  it "arrête le service avant la sauvegarde préalable" do
    with_admin do |admin|
      report, dry = run_dry(admin, 70_i64, "instance.upgrade", params(version: "0.2.0", from_version: "0.1.0"),
        databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      dry.calls.index!("service stop garde").should be < dry.calls.index!(&.starts_with?("pg_dump"))
    end
  end

  it "revient en arrière sur toute exception, même hors StepError" do
    dir = File.join(Dir.tempdir, "partiduo-agent-closure-#{Random::Secure.hex(4)}")
    config = PartiduoAgent::Config.new
    config.state_dir = dir
    config.backup_dir = File.join(dir, "backups")
    system = ExplodingSystem.new(config, ->(_line : String) { nil })
    system.databases << "partiduo_adm_garde"
    system.provisioned << "partiduo_adm_garde"
    system.releases["garde"] = "0.1.0"
    task = PartiduoAgent::TaskInfo.new(71_i64, "instance.upgrade", 1, "garde",
      JSON.parse(params(version: "0.2.0", from_version: "0.1.0").to_json), "spec@example.com")
    ctx = PartiduoAgent::Context.new(task, system, PartiduoAgent::Journal.new(File.join(dir, "tasks"), 71_i64))
    expect_raises(PartiduoAgent::StepError, /retour à 0.1.0/) { PartiduoAgent::Plans.run(ctx) }
    ctx.result["rolled_back"].as_bool.should be_true
    system.releases["garde"].should eq("0.1.0")
    # Migrations passées : base rendue à la sauvegarde préalable, service relancé.
    system.calls.should contain("dropdb partiduo_adm_garde")
    system.calls.any?(&.starts_with?("pg_restore")).should be_true
    system.stopped.includes?("garde").should be_false
  ensure
    FileUtils.rm_rf(dir) if dir
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
      dry.calls.should contain("partiduo-provision --files-only copie partiduo_adm_copie")
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

describe "partiduo-agent : scripts enveloppes de sudo (D-AFN-002)" do
  it "valident chaque argument avant tout geste" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    manage_dir = File.join(dir, "opt", "instances", "demo", "release", "bin")
    Dir.mkdir_p(manage_dir)
    Dir.mkdir_p(File.join(dir, "stage", "demo"))
    File.write(File.join(manage_dir, "partiduo-manage"), "#!/bin/sh\nprintf '%s\\n' \"DB=$DATABASE_URL\" \"$@\"\n", perm: 0o755)
    conf = File.join(dir, "helpers.conf")
    File.write(conf, <<-CONF)
      DOMAIN=partiduo.test
      INSTALL_ROOT=#{dir}/opt
      ETC_DIR=#{dir}/etc
      BACKUP_DIR=#{dir}/backups
      STAGE_DIR=#{dir}/stage
      PG_SOCKET=/tmp
      SYSTEM_ROOT=#{dir}/root
      CONF
    piege = File.join(dir, "piege")

    code, output, _ = helper("partiduo-agent-instance", conf, ["cli", "demo", "partiduo_rt_demo_5", "-", "status", "--task", "1"])
    code.should eq(0)
    output.lines.should eq(["DB=postgres:///partiduo_rt_demo_5?host=/tmp", "instance", "status", "--task", "1"])

    [
      ["cli", "demo", "partiduo_x;touch #{piege}", "-", "status"],
      ["cli", "demo", "partiduo_x $(touch #{piege})", "-", "status"],
      ["cli", "demo;touch #{piege}", "-", "-", "status"],
      ["cli", "admin", "-", "-", "status"],
      ["cli", "demo", "-", "-", "shell"],
      ["cli", "demo", "-", "../../x", "status"],
      ["cli", "demo", "-", "-", "backup-plan", "--list-file", "/etc/passwd"],
      ["cli", "demo", "-", "-", "backup-plan", "--list-file=#{dir}/backups/../x"],
      ["provision", "demo", "--manage", "/bin/sh"],
      ["provision", "demo", "--regime", "xx"],
      ["dump", "partiduo_demo", "/etc/x.dump"],
      ["createdb", "partiduo_admin"],
      ["release", "demo", "../../tmp"],
      ["frob"],
    ].each do |args|
      code, _, errors = helper("partiduo-agent-instance", conf, args)
      code.should eq(2)
      errors.should start_with("partiduo-agent-instance : ")
    end

    File.write(File.join(dir, "stage", "demo", "demo.env"), "PORT=8101\nLD_PRELOAD=/tmp/x.so\n")
    [
      ["install", "demo"],
      ["install", "demo x"],
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
    File.write(File.join(dir, "stage", "demo", "demo.env"), "PORT=8101\nDATABASE_URL=postgres:///partiduo_voisin?host=/tmp\n")
    _, _, errors = helper("partiduo-agent-root", conf, ["install", "demo"])
    errors.should contain("DATABASE_URL refusée")
    errors.should_not contain("partiduo_voisin")
    File.exists?(piege).should be_false
  ensure
    FileUtils.rm_rf(dir) if dir
  end
end
