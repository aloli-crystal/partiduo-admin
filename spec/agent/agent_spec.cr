# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

private def run_one(admin : AdminSpec::FakeAdmin, config : PartiduoAgent::Config) : PartiduoAgent::Runner
  runner = PartiduoAgent::Runner.new(config)
  runner.run_once.should be_true
  runner
end

private def dossier_params(slug = "demo", package = "app")
  {"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost", "database" => "",
   "modules" => ["accounting", "invoicing"], "extensions" => [] of String, "package" => package}
end

describe PartiduoAgent do
  it "refuse une administration jointe en clair hors de la machine" do
    config = PartiduoAgent::Config.new
    config.token = "x"
    config.admin_url = "http://admin.partiduo.app"
    expect_raises(ArgumentError, /HTTPS/) { config.validate! }
    config.admin_url = "https://admin.partiduo.app"
    config.validate!
  end

  it "s'authentifie par le jeton du serveur et ne fait rien sans tâche" do
    admin = AdminSpec::FakeAdmin.new
    config = admin.config
    PartiduoAgent::Runner.new(config).run_once.should be_false
    admin.headers.last["X-Partiduo-Agent-Mode"].should eq("dry-run")
    config.token = "mauvais"
    expect_raises(PartiduoAgent::ApiError, /401/) { PartiduoAgent::Runner.new(config).run_once }
  ensure
    admin.try(&.close)
  end

  it "crée une instance à blanc et rend base, version et lien d'invitation" do
    admin = AdminSpec::FakeAdmin.new
    params = dossier_params("demo-fr").merge({"name" => "Démo", "regime" => "fr", "locale" => "fr",
                                              "admin_email" => "patron@demo.fr", "siren" => "", "vat" => ""})
    admin.push(1_i64, "instance.create", params)
    run_one(admin, admin.config)
    report = admin.finished[1_i64]
    report["ok"].as_bool.should be_true, report.to_json
    report["result"]["database"].should eq("partiduo_adm_demo_fr")
    report["result"]["invitation_url"].as_s.should contain("/invitation/")
    report["result"]["certificate"]["issued"].as_bool.should be_false
    admin.logs[1_i64].join("\n").should contain("[à blanc] partiduo-provision demo-fr")
  ensure
    admin.try(&.close)
  end

  it "refuse un type de tâche hors de la liste fermée" do
    admin = AdminSpec::FakeAdmin.new
    admin.push(2_i64, "shell.exec", {"command" => "rm -rf /"})
    run_one(admin, admin.config)
    admin.finished[2_i64]["ok"].as_bool.should be_false
    admin.finished[2_i64]["error"].as_s.should contain("refusé")
  ensure
    admin.try(&.close)
  end

  it "reprend une tâche interrompue sans refaire les étapes faites" do
    admin = AdminSpec::FakeAdmin.new
    config = admin.config
    config.fail_on = "tar"
    admin.push(3_i64, "backup.run", dossier_params.merge({"kind" => "scheduled"}))
    runner = PartiduoAgent::Runner.new(config)
    runner.run_once
    admin.finished[3_i64]["ok"].as_bool.should be_false
    dry = runner.last_system.as(PartiduoAgent::DrySystem)
    dry.calls.count(&.starts_with?("pg_dump")).should eq(1)

    admin.push(3_i64, "backup.run", dossier_params.merge({"kind" => "scheduled"}), attempt: 2)
    runner.run_once
    report = admin.finished[3_i64]
    report["ok"].as_bool.should be_true
    dry.calls.count(&.starts_with?("pg_dump")).should eq(1)
    admin.logs[3_i64].join("\n").should contain("déjà faite (reprise)")
    report["result"]["path"].as_s.should end_with(".dump")
    report["result"]["sha256"].as_s.size.should eq(64)
  ensure
    admin.try(&.close)
  end

  it "archive : lecture seule, sauvegarde figée vérifiée, service arrêté" do
    admin = AdminSpec::FakeAdmin.new
    admin.push(4_i64, "instance.archive", dossier_params.merge({"reason" => "cessation"}))
    runner = run_one(admin, admin.config)
    report = admin.finished[4_i64]
    report["ok"].as_bool.should be_true
    report["result"]["backup"]["verified"].as_bool.should be_true
    calls = runner.last_system.as(PartiduoAgent::DrySystem).calls
    calls.index!(&.starts_with?("instance read-only")).should be < calls.index!(&.starts_with?("pg_dump"))
    calls.last.should start_with("service stop")
  ensure
    admin.try(&.close)
  end

  it "crée une instance servie par le paquet devel, interrogée par l'outil de ce paquet" do
    admin = AdminSpec::FakeAdmin.new
    params = dossier_params("essai", "devel").merge({"name" => "Essai", "regime" => "fr", "locale" => "fr",
                                                     "admin_email" => "patron@essai.fr", "siren" => "", "vat" => ""})
    admin.push(5_i64, "instance.create", params)
    runner = run_one(admin, admin.config)
    report = admin.finished[5_i64]
    report["ok"].as_bool.should be_true, report.to_json
    report["result"]["version"].should eq("0.1.0")
    dry = runner.last_system.as(PartiduoAgent::DrySystem)
    dry.packages["essai"].should eq("devel")
    dry.calls.should contain("partiduo-provision essai partiduo_adm_essai devel")
  ensure
    admin.try(&.close)
  end

  it "ne connaît plus de montée de version : la mise à jour des paquets relève de beryl" do
    admin = AdminSpec::FakeAdmin.new
    admin.push(6_i64, "instance.upgrade", dossier_params.merge({"version" => "0.2.0", "from_version" => "0.1.0"}))
    runner = run_one(admin, admin.config)
    admin.finished[6_i64]["ok"].as_bool.should be_false
    admin.finished[6_i64]["error"].as_s.should contain("type de tâche refusé")
    runner.last_system.as(PartiduoAgent::DrySystem).calls.should be_empty
  ensure
    admin.try(&.close)
  end

  it "transmet la double validation au recours d'accès et rend le lien" do
    admin = AdminSpec::FakeAdmin.new
    admin.push(7_i64, "instance.admin_invite", dossier_params.merge({"email" => "gerant@demo.fr", "reason" => "départ",
                                                                     "approval_ref" => "DV-AAAA-BBBB", "approvers" => ["a@x.fr", "b@x.fr"]}))
    runner = run_one(admin, admin.config)
    admin.finished[7_i64]["result"]["url"].as_s.should contain("invitation")
    call = runner.last_system.as(PartiduoAgent::DrySystem).calls.find!(&.starts_with?("instance admin-invite"))
    call.should contain("--approval-ref DV-AAAA-BBBB")
    call.should contain("--approvers a@x.fr,b@x.fr")
  ensure
    admin.try(&.close)
  end

  it "relève la supervision : disque et état de chaque dossier" do
    admin = AdminSpec::FakeAdmin.new
    admin.push(8_i64, "supervision.check", {"dossiers" => [{"slug" => "absent", "host" => "absent.partiduo.localhost", "database" => ""}]})
    run_one(admin, admin.config)
    result = admin.finished[8_i64]["result"]
    result["disk"]["total_bytes"].as_i64.should be > 0
    entry = result["dossiers"][0]
    entry["service"].should eq("running")
    entry["database"].should eq("unavailable")
  ensure
    admin.try(&.close)
  end
end

describe PartiduoAgent::LocalSystem do
  it "refuse toute base qui n'est pas partiduo_adm_* en mode local" do
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Local
    system = PartiduoAgent::LocalSystem.new(config, ->(_line : String) { nil })
    expect_raises(PartiduoAgent::StepError, /partiduo_adm_/) { system.dropdb("partiduo_dev") }
    expect_raises(PartiduoAgent::StepError, /partiduo_adm_/) { system.createdb("postgres") }
    expect_raises(PartiduoAgent::StepError, /hors du répertoire/) { system.remove("/etc/passwd") }
  end

  it "sauvegarde puis relit réellement une base partiduo_adm_* (restauration test locale)" do
    base = File.join(Dir.tempdir, "partiduo-agent-local-#{Random::Secure.hex(4)}")
    Dir.mkdir_p(base)
    manage = File.join(base, "fake-manage")
    File.write(manage, <<-SH, perm: 0o755)
      #!/bin/sh
      # Interface d'instance simulée (contrat 1.0.0) sur une vraie base.
      shift
      action="$1"
      case "$action" in
        version) echo '{"contract":"1.0.0","action":"version","ok":true,"data":{"version":"0.1.0","contract":"1.0.0"}}' ;;
        status)
          if psql "$DATABASE_URL" -tAc 'SELECT count(*) FROM spec_marker' >/dev/null 2>&1; then
            echo '{"contract":"1.0.0","action":"status","ok":true,"data":{"version":"0.1.0","provisioned":true,"migrations":{"applied":3,"pending":0}}}'
          else
            echo '{"contract":"1.0.0","action":"status","ok":false,"error":{"code":"database_unavailable","reason":"database.unavailable","message":"base"}}'
            exit 6
          fi ;;
        backup-plan)
          while [ $# -gt 0 ]; do [ "$1" = "--list-file" ] && : > "$2"; shift; done
          echo '{"contract":"1.0.0","action":"backup-plan","ok":true,"data":{"media_root":"/nonexistent","file_count":0,"missing":[]}}' ;;
        *) echo '{"contract":"1.0.0","ok":false,"error":{"code":"usage"}}'; exit 2 ;;
      esac
      SH
    database = "partiduo_adm_spec_local"
    env = {"PGHOST" => (ENV["PGHOST"]? || "/tmp")}
    Process.run("dropdb", ["--if-exists", database], env: env)
    Process.run("createdb", ["--encoding=UTF8", database], env: env).success?.should be_true
    Process.run("psql", ["-d", database, "-c", "CREATE TABLE spec_marker (id int); INSERT INTO spec_marker VALUES (1);"], env: env)

    admin = AdminSpec::FakeAdmin.new
    config = admin.config(PartiduoAgent::Mode::Local)
    config.manage = manage
    config.pg_socket = ENV["PGHOST"]? || "/tmp"
    params = {"slug" => "spec-local", "host" => "spec-local.partiduo.localhost", "domain" => "partiduo.localhost",
              "database" => database, "kind" => "manual"}
    admin.push(20_i64, "backup.run", params)
    run_one(admin, config)
    backup = admin.finished[20_i64]
    backup["ok"].as_bool.should be_true, backup.to_json
    path = backup["result"]["path"].as_s
    File.exists?(path).should be_true
    File.exists?(backup["result"]["media_path"].as_s).should be_true

    admin.push(21_i64, "backup.test_restore", params.merge({"path" => path, "media_path" => backup["result"]["media_path"].as_s,
                                                            "sha256" => backup["result"]["sha256"].as_s}))
    run_one(admin, config)
    report = admin.finished[21_i64]
    report["ok"].as_bool.should be_true
    report["result"]["verified"].as_bool.should be_true
    # La base temporaire est supprimée.
    output = IO::Memory.new
    Process.run("psql", ["-d", "postgres", "-tAc", "SELECT count(*) FROM pg_database WHERE datname LIKE 'partiduo_adm_rt_spec_local%'"], env: env, output: output)
    output.to_s.strip.should eq("0")
  ensure
    admin.try(&.close)
    Process.run("dropdb", ["--if-exists", "partiduo_adm_spec_local"], env: {"PGHOST" => (ENV["PGHOST"]? || "/tmp")})
  end
end

describe PartiduoAgent::Plans do
  it "a un plan pour chaque type de la liste fermée, et aucun autre" do
    PartiduoAgent::Plans::PLANS.keys.sort!.should eq(PartiduoAdmin::Protocol::KINDS.sort)
  end
end
