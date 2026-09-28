# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Exécutant `partiduo-agent` : garde-fous et cas limites (ADR-008 D4) —
# contrat d'instance, versions et chemins refusés, bases protégées, ordre
# des gestes, reprise, configuration.

private def run_task(admin : AdminSpec::FakeAdmin, config : PartiduoAgent::Config, id : Int64, kind : String,
                     params : Hash, databases = [] of String) : {JSON::Any, PartiduoAgent::Runner}
  admin.push(id, kind, params)
  runner = PartiduoAgent::Runner.new(config)
  unless databases.empty?
    # Bases déjà présentes sur le serveur simulé.
    dry = runner.build_system(->(_line : String) { nil }).as(PartiduoAgent::DrySystem)
    databases.each { |database| dry.databases << database; dry.provisioned << database }
  end
  runner.run_once.should be_true
  {admin.finished[id], runner}
end

private def base_params(slug = "garde")
  {"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost", "database" => "",
   "modules" => ["accounting", "invoicing"], "extensions" => [] of String, "version" => "0.1.0"}
end

private def dry_calls(runner : PartiduoAgent::Runner) : Array(String)
  runner.last_system.as(PartiduoAgent::DrySystem).calls
end

private def with_admin(&)
  admin = AdminSpec::FakeAdmin.new
  begin
    yield admin
  ensure
    admin.close
  end
end

describe "partiduo-agent : garde-fous" do
  it "refuse une interface d'instance d'une autre version majeure du contrat" do
    with_admin do |admin|
      config = admin.config(PartiduoAgent::Mode::Local)
      Dir.mkdir_p(config.state_dir)
      manage = File.join(config.state_dir, "manage-v2")
      File.write(manage, <<-SH, perm: 0o755)
        #!/bin/sh
        echo '{"contract":"2.0.0","action":"version","ok":true,"data":{"version":"9.0.0","contract":"2.0.0"}}'
        SH
      config.manage = manage
      report, _ = run_task(admin, config, 30_i64, "instance.modules", base_params.merge({"enable" => ["analytic"], "disable" => [] of String}))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("contrat d'instance")
    end
  end

  it "refuse une version qui serait un chemin, avant tout geste" do
    with_admin do |admin|
      create = base_params("chemin").merge({"version" => "../../../tmp/piege", "name" => "X", "regime" => "fr", "locale" => "fr",
                                            "admin_email" => "a@b.fr", "siren" => "", "vat" => ""})
      report, runner = run_task(admin, admin.config, 31_i64, "instance.create", create)
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("version invalide")
      dry_calls(runner).should be_empty

      upgrade = base_params("chemin").merge({"version" => "0.2.0/../../x", "from_version" => "0.1.0"})
      report, runner = run_task(admin, admin.config, 32_i64, "instance.upgrade", upgrade)
      report["ok"].as_bool.should be_false
      dry_calls(runner).none?(&.starts_with?("release")).should be_true
    end
  end

  it "n'efface aucun fichier hors du répertoire des sauvegardes, même à blanc" do
    with_admin do |admin|
      config = admin.config
      inside = File.join(config.backup_dir, "garde", "b.dump")
      report, runner = run_task(admin, config, 33_i64, "backup.prune", base_params.merge({"paths" => [inside]}))
      report["ok"].as_bool.should be_true
      dry_calls(runner).should contain("rm #{inside}")

      %w[/etc/passwd ../../etc/passwd].each_with_index do |path, index|
        outside = path.starts_with?('/') ? path : File.join(config.backup_dir, path)
        report, _ = run_task(admin, config, 34_i64 + index, "backup.prune", base_params.merge({"paths" => [outside]}))
        report["ok"].as_bool.should be_false
        report["error"].as_s.should contain("hors du répertoire")
      end
      sibling = config.backup_dir + "-voisin/x.dump"
      report, _ = run_task(admin, config, 36_i64, "backup.restore", base_params.merge({"path" => sibling, "target" => "replace"}))
      report["ok"].as_bool.should be_false
    end
  end

  it "ne relit pas une sauvegarde dont l'empreinte a changé" do
    with_admin do |admin|
      config = admin.config
      path = File.join(config.backup_dir, "garde", "b.dump")
      report, runner = run_task(admin, config, 37_i64, "backup.test_restore", base_params.merge({"path" => path, "sha256" => "0" * 64}))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("empreinte")
      dry_calls(runner).none?(&.starts_with?("createdb")).should be_true
    end
  end

  it "refuse une restauration dans une instance neuve au sous-domaine réservé" do
    with_admin do |admin|
      config = admin.config
      path = File.join(config.backup_dir, "garde", "b.dump")
      report, _ = run_task(admin, config, 38_i64, "backup.restore",
        base_params.merge({"path" => path, "target" => "new", "new_slug" => "admin", "new_host" => "admin.partiduo.localhost"}))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("sous-domaine invalide")
    end
  end

  it "désactive avant d'activer, et selon les dépendances que rend l'instance (D-AFN-006)" do
    with_admin do |admin|
      # Le Suivi requiert la Facturation : il se désactive avant elle, quel
      # que soit l'ordre reçu.
      params = base_params.merge({"enable" => ["analytic"], "disable" => ["invoicing", "followup"]})
      report, runner = run_task(admin, admin.config, 39_i64, "instance.modules", params, databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      calls = dry_calls(runner).select { |call| call.starts_with?("instance enable") || call.starts_with?("instance disable") }
      calls.map(&.split(' ')[0, 4].join(' ')).should eq(["instance disable garde followup", "instance disable garde invoicing",
                                                         "instance enable garde analytic"])
    end
  end

  it "supprime définitivement : service retiré, base supprimée, puis sauvegardes effacées" do
    with_admin do |admin|
      config = admin.config
      backups = [File.join(config.backup_dir, "garde", "a.dump"), File.join(config.backup_dir, "garde", "a.media.tar.gz")]
      params = base_params.merge({"approval_ref" => "DV-AAAA-BBBB", "approvers" => ["a@x.fr", "b@x.fr"], "backups" => backups})
      report, runner = run_task(admin, config, 40_i64, "instance.delete", params)
      report["ok"].as_bool.should be_true
      calls = dry_calls(runner)
      calls.index!(&.starts_with?("retrait")).should be < calls.index!(&.starts_with?("dropdb"))
      calls.index!(&.starts_with?("dropdb")).should be < calls.index!(&.starts_with?("rm"))
      calls.count(&.starts_with?("rm")).should eq(2)
      admin.logs[40_i64].join("\n").should contain("DV-AAAA-BBBB")
    end
  end

  it "ne restaure pas la base quand la montée échoue avant la bascule" do
    with_admin do |admin|
      config = admin.config
      config.fail_on = "service stop"
      report, runner = run_task(admin, config, 41_i64, "instance.upgrade", base_params.merge({"version" => "0.2.0", "from_version" => "0.1.0"}))
      report["ok"].as_bool.should be_false
      report["result"]["rolled_back"].as_bool.should be_true
      calls = dry_calls(runner)
      calls.any?(&.starts_with?("pg_restore")).should be_false
      calls.any?(&.starts_with?("dropdb")).should be_false
      calls.last.should eq("service start garde")
    end
  end

  it "refuse une montée sans version cible" do
    with_admin do |admin|
      report, _ = run_task(admin, admin.config, 42_i64, "instance.upgrade", base_params.merge({"version" => ""}))
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("version cible manquante")
    end
  end
end

describe "partiduo-agent : bases protégées" do
  it "n'accepte en production que les bases partiduo_*, jamais celle de l'administration" do
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Production
    system = PartiduoAgent::ProductionSystem.new(config, ->(_line : String) { nil })
    system.guard_database!("partiduo_demo_fr")
    expect_raises(PartiduoAgent::StepError, /refusée/) { system.guard_database!("partiduo_admin") }
    expect_raises(PartiduoAgent::StepError, /refusée/) { system.guard_database!("postgres") }
    expect_raises(PartiduoAgent::StepError, /invalide/) { system.guard_database!("partiduo_x; DROP") }
    system.database_for("demo-fr").should eq("partiduo_demo_fr")
    system.scratch_database("demo-fr", 12_i64).should eq("partiduo_rt_demo_fr_12")
  end

  it "nomme les bases de restauration test dans la limite de PostgreSQL et sous le préfixe du mode" do
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Local
    system = PartiduoAgent::LocalSystem.new(config, ->(_line : String) { nil })
    name = system.scratch_database("a" * 40, 123456789_i64)
    name.size.should be <= 63
    name.should start_with("partiduo_adm_rt_")
    system.guard_database!(name)
    expect_raises(PartiduoAgent::StepError, /partiduo_adm_/) { system.guard_database!("partiduo_demo") }
  end
end

describe "partiduo-agent : configuration et reprise" do
  it "exige un jeton, et HTTPS hors de la machine et toujours en production" do
    config = PartiduoAgent::Config.new
    config.admin_url = "https://admin.partiduo.app"
    expect_raises(ArgumentError, /jeton/) { config.validate! }
    config.token = "x"
    config.admin_url = "http://admin.partiduo.localhost:8200"
    config.validate!
    config.admin_url = "http://127.0.0.1.nip.io"
    expect_raises(ArgumentError, /HTTPS/) { config.validate! }
    config.admin_url = "http://127.0.0.1:8200"
    config.mode = PartiduoAgent::Mode::Production
    expect_raises(ArgumentError, /HTTPS/) { config.validate! }
  end

  it "garde sur disque, en 0600, les étapes faites d'une tâche et les rend à la reprise" do
    dir = File.join(Dir.tempdir, "partiduo-journal-#{Random::Secure.hex(4)}")
    journal = PartiduoAgent::Journal.new(dir, 7_i64)
    journal.mark("backup : base")
    journal["backup.stamp"] = "20260928T100000Z"
    (File.info(journal.path).permissions.value & 0o777).should eq(0o600)
    resumed = PartiduoAgent::Journal.new(dir, 7_i64)
    resumed.done?("backup : base").should be_true
    resumed["backup.stamp"]?.should eq("20260928T100000Z")
    PartiduoAgent::Journal.new(dir, 8_i64).done.should be_empty
    File.write(resumed.path, "{illisible")
    PartiduoAgent::Journal.new(dir, 7_i64).done.should be_empty
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  it "rend une erreur interne lisible quand l'interface d'instance ne répond pas en JSON" do
    config = PartiduoAgent::Config.new
    system = PartiduoAgent::LocalSystem.new(config, ->(_line : String) { nil })
    reply = PartiduoAgent::InstanceReply.new(1, JSON.parse(system.reply_line("Segmentation fault\n", "boom")))
    reply.ok?.should be_false
    reply.error_code.should eq("internal")
    reply.message.should contain("boom")
    # Code de sortie nul mais `ok` faux : échec.
    PartiduoAgent::InstanceReply.new(0, JSON.parse(%({"ok":false}))).ok?.should be_false
  end
end
