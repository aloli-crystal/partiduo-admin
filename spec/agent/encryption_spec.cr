# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Sauvegardes chiffrées de bout en bout (D-CHF-001 à D-CHF-012) : l'exécutant
# en mode local, sur de vraies bases `partiduo_adm_*`, `pg_dump`, `tar` et
# `pg_restore`, pour les trois modes (aucun, clé du serveur, clé du cabinet).

private alias Crypto = PartiduoAdmin::BackupCrypto

private PG_HOST = ENV["PGHOST"]? || "/tmp"

private def pg_env : Hash(String, String)
  {"PGHOST" => PG_HOST}
end

private def psql(database : String, sql : String) : String
  output = IO::Memory.new
  Process.run("psql", ["-X", "-d", database, "-tAc", sql], env: pg_env, output: output)
  output.to_s.strip
end

# Interface d'instance simulée (contrat 1.0.0) sur une vraie base, avec de
# vraies pièces jointes sous `PARTIDUO_MEDIA_ROOT`.
private def fake_manage(directory : String) : String
  path = File.join(directory, "fake-manage")
  File.write(path, <<-SH, perm: 0o755)
    #!/bin/sh
    shift
    action="$1"
    case "$action" in
      version) echo '{"contract":"1.0.0","action":"version","ok":true,"data":{"version":"0.1.0","contract":"1.0.0"}}' ;;
      status)
        if psql -X "$DATABASE_URL" -tAc 'SELECT count(*) FROM spec_marker' >/dev/null 2>&1; then
          echo '{"contract":"1.0.0","action":"status","ok":true,"data":{"version":"0.1.0","provisioned":true,"migrations":{"applied":3,"pending":0}}}'
        else
          echo '{"contract":"1.0.0","action":"status","ok":false,"error":{"code":"database_unavailable","reason":"database.unavailable","message":"base"}}'
          exit 6
        fi ;;
      backup-plan)
        while [ $# -gt 0 ]; do
          if [ "$1" = "--list-file" ]; then (cd "$PARTIDUO_MEDIA_ROOT" 2>/dev/null && find . -type f | sed 's|^\\./||') > "$2"; fi
          shift
        done
        echo "{\\"contract\\":\\"1.0.0\\",\\"action\\":\\"backup-plan\\",\\"ok\\":true,\\"data\\":{\\"media_root\\":\\"$PARTIDUO_MEDIA_ROOT\\",\\"file_count\\":2,\\"missing\\":[]}}" ;;
      *) echo '{"contract":"1.0.0","ok":false,"error":{"code":"usage"}}'; exit 2 ;;
    esac
    SH
  path
end

private class LocalBench
  getter admin = AdminSpec::FakeAdmin.new
  getter config : PartiduoAgent::Config
  getter database : String
  getter slug : String
  @next = 100_i64

  def initialize(@slug : String)
    @database = "partiduo_adm_#{@slug.tr("-", "_")}"
    @config = admin.config(PartiduoAgent::Mode::Local)
    Dir.mkdir_p(config.state_dir)
    config.manage = fake_manage(config.state_dir)
    config.pg_socket = PG_HOST
    Process.run("dropdb", ["--if-exists", database], env: pg_env)
    Process.run("createdb", ["--encoding=UTF8", database], env: pg_env).success?.should be_true
    # Plusieurs tables liées, index et données : de quoi éprouver pg_restore
    # lisant son entrée standard.
    psql(database, "CREATE TABLE spec_marker (id int PRIMARY KEY, label text); " \
                   "CREATE TABLE spec_line (id serial PRIMARY KEY, marker int REFERENCES spec_marker(id), amount numeric(12,2)); " \
                   "CREATE INDEX spec_line_marker ON spec_line (marker); " \
                   "INSERT INTO spec_marker VALUES (1, 'avant'); " \
                   "INSERT INTO spec_line (marker, amount) SELECT 1, g * 1.5 FROM generate_series(1, 20000) g;")
    media = media_root
    Dir.mkdir_p(File.join(media, "factures"))
    File.write(File.join(media, "factures", "F-001.pdf"), "%PDF facture confidentielle")
    File.write(File.join(media, "note.txt"), "pièce jointe")
  end

  def media_root : String
    File.join(config.work_dir, "instances", slug, "media")
  end

  def params(extra = {} of String => JSON::Any) : Hash(String, JSON::Any)
    base = JSON.parse({"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost",
                       "database" => database, "package" => "app"}.to_json).as_h
    base.merge(extra)
  end

  def run(kind : String, extra : Hash(String, JSON::Any), data_keys : Array(String)? = nil) : JSON::Any
    id = (@next += 1)
    admin.push(id, kind, params(extra), data_keys: data_keys)
    PartiduoAgent::Runner.new(config).run_once.should be_true
    admin.finished[id]
  end

  def backup_files : Array(String)
    Dir.glob(File.join(config.backup_dir, slug, "*")).map { |path| File.basename(path) }.sort!
  end

  def close : Nil
    admin.close
    Process.run("dropdb", ["--if-exists", database], env: pg_env)
    Process.run("dropdb", ["--if-exists", "partiduo_adm_rt_#{slug.tr("-", "_")}"], env: pg_env)
  end
end

private def any(value) : JSON::Any
  JSON.parse(value.to_json)
end

private def source(result : JSON::Any) : Hash(String, JSON::Any)
  enc = result["encryption"]
  {"path" => result["path"], "media_path" => result["media_path"], "sha256" => result["sha256"],
   "media_sha256" => result["media_sha256"],
   "backup_encryption" => any({"mode" => enc["mode"].as_s, "key_fingerprint" => enc["key_fingerprint"]?.try(&.as_s) || "",
                               "commitment" => enc["commitment"]?.try(&.as_s) || ""})}
end

private def with_bench(slug : String, &)
  bench = LocalBench.new(slug)
  begin
    yield bench
  ensure
    bench.close
  end
end

describe "partiduo-agent : sauvegardes chiffrées en mode local (D-CHF-001 à D-CHF-007)" do
  it "aucun chiffrement : sauvegarde et restauration test comme avant" do
    with_bench("chf-aucun") do |bench|
      backup = bench.run("backup.run", {"kind" => any("manual"), "encryption" => any({"mode" => "none"})})
      backup["ok"].as_bool.should be_true, backup.to_json
      result = backup["result"]
      result["path"].as_s.should end_with(".dump")
      result["encryption"]["mode"].should eq("none")
      tested = bench.run("backup.test_restore", source(result).reject("backup_encryption"))
      tested["ok"].as_bool.should be_true, tested.to_json
      tested["result"]["check"].should eq("full")
    end
  end

  it "clé du serveur : rien en clair sur le disque, le serveur relit et restaure seul, pièces jointes comprises" do
    with_bench("chf-serveur") do |bench|
      backup = bench.run("backup.run", {"kind" => any("manual"), "encryption" => any({"mode" => "server"})})
      backup["ok"].as_bool.should be_true, backup.to_json
      result = backup["result"]
      result["path"].as_s.should end_with(".dump.enc")
      result["media_path"].as_s.should end_with(".media.tar.gz.enc")
      result["encryption"]["mode"].should eq("server")
      result["encryption"]["wrapped_key"].as_s.should_not be_empty
      # Aucun fichier en clair : ni base, ni archive, ni fichier partiel.
      files = bench.backup_files
      files.count(&.ends_with?(".enc")).should eq(2)
      files.none? { |name| name.ends_with?(".dump") || name.ends_with?(".tar.gz") || name.ends_with?(".part") }.should be_true
      dump = File.read(result["path"].as_s)
      dump.starts_with?("PDUOBAK").should be_true
      dump.includes?("spec_marker").should be_false
      File.read(result["media_path"].as_s).includes?("facture confidentielle").should be_false
      # Clé du serveur créée dans l'état de l'exécutant, en 0600, empreinte annoncée.
      key = Crypto::ServerKey.load(bench.config.server_key_path)
      (File.info(bench.config.server_key_path).permissions.value & 0o077).should eq(0)
      result["encryption"]["key_fingerprint"].should eq(key.fingerprint)
      Digest::SHA256.new.file(result["path"].as_s).hexfinal.should eq(result["sha256"].as_s)
      # Journal de reprise effacé : aucune clé de données ne reste.
      Dir.glob(File.join(bench.config.state_dir, "tasks", "*")).should be_empty

      tested = bench.run("backup.test_restore", source(result))
      tested["ok"].as_bool.should be_true, tested.to_json
      tested["result"]["check"].should eq("full")
      tested["result"]["verified"].as_bool.should be_true

      # Remplacement : la base et les pièces jointes reviennent à la sauvegarde.
      psql(bench.database, "UPDATE spec_marker SET label = 'après'; DELETE FROM spec_line WHERE id > 10")
      File.delete(File.join(bench.media_root, "factures", "F-001.pdf"))
      restored = bench.run("backup.restore", source(result).merge({"target"     => any("replace"),
                                                                   "encryption" => any({"mode" => "server"})}))
      restored["ok"].as_bool.should be_true, restored.to_json
      psql(bench.database, "SELECT label FROM spec_marker").should eq("avant")
      psql(bench.database, "SELECT count(*) FROM spec_line").should eq("20000")
      File.read(File.join(bench.media_root, "factures", "F-001.pdf")).should eq("%PDF facture confidentielle")
      # Sauvegarde de sûreté chiffrée elle aussi.
      restored["result"]["safety_backup"]["encryption"]["mode"].should eq("server")
    end
  end

  it "clé du cabinet : le serveur ne peut pas relire ; restauration test par l'enveloppe, restauration avec la clé fournie" do
    pair = AdminSpec::Keys.pair("a")
    public_key = Crypto::PublicKey.new(pair.public_pem)
    settings = any({"mode" => "cabinet", "public_key" => pair.public_pem, "key_fingerprint" => public_key.fingerprint})
    with_bench("chf-cabinet") do |bench|
      backup = bench.run("backup.run", {"kind" => any("manual"), "encryption" => settings})
      backup["ok"].as_bool.should be_true, backup.to_json
      result = backup["result"]
      enc = result["encryption"]
      enc["mode"].should eq("cabinet")
      enc["key_fingerprint"].should eq(public_key.fingerprint)
      File.read(result["path"].as_s).includes?("spec_marker").should be_false
      Dir.glob(File.join(bench.config.state_dir, "tasks", "*")).should be_empty

      # Sans la clé : empreinte et enveloppe seulement, et le résultat le dit.
      tested = bench.run("backup.test_restore", source(result))
      tested["ok"].as_bool.should be_true, tested.to_json
      tested["result"]["check"].should eq("envelope")
      tested["result"]["verified"].as_bool.should be_false
      bench.admin.logs[102_i64].join("\n").should contain("vérifiable seulement avec la clé du cabinet")

      # Restauration sans la clé : refusée avant tout geste.
      psql(bench.database, "UPDATE spec_marker SET label = 'après'")
      refused = bench.run("backup.restore", source(result).merge({"target" => any("replace"), "encryption" => settings}))
      refused["ok"].as_bool.should be_false
      refused["error"].as_s.should contain("clé")
      psql(bench.database, "SELECT label FROM spec_marker").should eq("après")

      # La clé de données, déchiffrée par l'admin du cabinet avec sa clé
      # privée (ici comme dans son navigateur), permet tout.
      private_key = Crypto::PrivateKey.new(pair.private_pem, AdminSpec::Keys::PASSPHRASE)
      data_key = Base64.strict_encode(private_key.unwrap(Base64.decode(enc["wrapped_key"].as_s)))
      full = bench.run("backup.test_restore", source(result), data_keys: [data_key])
      full["ok"].as_bool.should be_true, full.to_json
      full["result"]["check"].should eq("full")

      # Mauvaise clé : refusée.
      wrong = bench.run("backup.restore", source(result).merge({"target" => any("replace"), "encryption" => settings}),
        data_keys: [Base64.strict_encode(Crypto.random_key)])
      wrong["ok"].as_bool.should be_false
      psql(bench.database, "SELECT label FROM spec_marker").should eq("après")

      restored = bench.run("backup.restore", source(result).merge({"target" => any("replace"), "encryption" => settings}),
        data_keys: [data_key])
      restored["ok"].as_bool.should be_true, restored.to_json
      psql(bench.database, "SELECT label FROM spec_marker").should eq("avant")
      psql(bench.database, "SELECT sum(amount) FROM spec_line").should eq("300015000.00")
      # Aucune clé de données laissée sur le disque par les tâches.
      Dir.glob(File.join(bench.config.state_dir, "tasks", "*")).each do |journal|
        File.read(journal).includes?("secret.").should be_false
      end
    end
  end

  it "refuse une sauvegarde chiffrée falsifiée (empreinte, puis authentification)" do
    with_bench("chf-falsifie") do |bench|
      backup = bench.run("backup.run", {"kind" => any("manual"), "encryption" => any({"mode" => "server"})})
      result = backup["result"]
      path = result["path"].as_s
      File.open(path, "r+") do |file|
        file.seek(400)
        byte = file.read_byte || raise "octet absent"
        file.seek(400)
        file.write_byte(byte ^ 0x20_u8)
      end
      digest = bench.run("backup.test_restore", source(result))
      digest["ok"].as_bool.should be_false
      digest["error"].as_s.should contain("empreinte")
      # Sans empreinte fournie : l'authentification GCM refuse le fichier.
      unsigned = source(result).merge({"sha256" => any(""), "target" => any("replace"),
                                       "encryption" => any({"mode" => "server"})})
      psql(bench.database, "UPDATE spec_marker SET label = 'intacte'")
      refused = bench.run("backup.restore", unsigned)
      refused["ok"].as_bool.should be_false
      refused["error"].as_s.should contain("altérée")
      psql(bench.database, "SELECT label FROM spec_marker").should eq("intacte")
    end
  end
end

describe "partiduo-agent : sauvegardes chiffrées à blanc et en production" do
  it "compte une archive chiffrée dans la durée légale (suppression définitive et élagage refusés)" do
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Local
    config.backup_dir = File.join(Dir.tempdir, "partiduo-chf-archive-#{Random::Secure.hex(4)}")
    system = PartiduoAgent::LocalSystem.new(config, ->(_line : String) { nil })
    Dir.mkdir_p(system.backup_root("garde"))
    path = File.join(system.backup_root("garde"), "archive-20260101T000000Z.dump.enc")
    File.write(path, "chiffré")
    system.archive_dates("garde").should eq([Time.utc(2026, 1, 1)])
    expect_raises(PartiduoAgent::StepError, /durée légale/) { system.guard_retention!("garde", Time.utc(2030, 1, 1)) }
    expect_raises(PartiduoAgent::StepError, /durée légale/) { system.guard_archive_removal!(path, Time.utc(2030, 1, 1)) }
  end

  it "chiffre les sauvegardes d'archivage et de sûreté, et relit l'archive chiffrée à la restauration" do
    admin = AdminSpec::FakeAdmin.new
    config = admin.config
    params = {"slug" => "demo", "host" => "demo.partiduo.localhost", "domain" => "partiduo.localhost", "database" => "",
              "package" => "app", "encryption" => {"mode" => "server"}}
    admin.push(1_i64, "instance.archive", params.merge({"reason" => "fin"}))
    runner = PartiduoAgent::Runner.new(config)
    runner.run_once
    report = admin.finished[1_i64]
    report["ok"].as_bool.should be_true, report.to_json
    report["result"]["backup"]["path"].as_s.should end_with(".dump.enc")
    report["result"]["backup"]["encryption"]["mode"].should eq("server")
    calls = runner.last_system.as(PartiduoAgent::DrySystem).calls
    calls.should contain("déchiffrement | pg_restore --list #{report["result"]["backup"]["path"].as_s}")

    archive = report["result"]["backup"]["path"].as_s
    admin.push(2_i64, "backup.restore", params.merge({"target" => "replace", "path" => archive,
                                                      "backup_encryption" => {"mode" => "server"}}))
    runner.run_once
    restored = admin.finished[2_i64]
    restored["ok"].as_bool.should be_true, restored.to_json
    restored["result"]["safety_backup"]["path"].as_s.should end_with(".dump.enc")
    restored["result"]["safety_backup"]["path"].as_s.should contain("pre-restore")
    runner.last_system.as(PartiduoAgent::DrySystem).calls.should contain("déchiffrement | pg_restore #{archive} partiduo_adm_demo")
  ensure
    admin.try(&.close)
  end

  it "refuse un mode inconnu et une clé du cabinet dont l'empreinte n'est pas celle annoncée" do
    admin = AdminSpec::FakeAdmin.new
    pair = AdminSpec::Keys.pair("a")
    base = {"slug" => "demo", "host" => "demo.partiduo.localhost", "domain" => "partiduo.localhost", "database" => "",
            "kind" => "manual"}
    admin.push(1_i64, "backup.run", base.merge({"encryption" => {"mode" => "rot13"}}))
    admin.push(2_i64, "backup.run", base.merge({"encryption" => {"mode" => "cabinet", "public_key" => pair.public_pem,
                                                                 "key_fingerprint" => "00" * 32}}))
    runner = PartiduoAgent::Runner.new(admin.config)
    runner.run_once
    runner.run_once
    admin.finished[1_i64]["error"].as_s.should contain("mode de chiffrement inconnu")
    admin.finished[2_i64]["error"].as_s.should contain("empreinte")
  ensure
    admin.try(&.close)
  end

  it "fait passer le clair par l'entrée et la sortie standard de l'enveloppe de sudo, jamais par un fichier" do
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Production
    config.domain = "partiduo.app"
    config.backup_dir = File.join(Dir.tempdir, "partiduo-chf-prod-#{Random::Secure.hex(4)}")
    streams = [] of Array(String)
    system = StreamRecordingProduction.new(config, ->(_line : String) { nil }, streams)
    helper = ["/usr/local/bin/sudo", "-n", "-u", "partiduo", "/usr/local/libexec/partiduo-agent/partiduo-agent-instance"]
    root = system.backup_root("garde")
    sealer = Crypto::Sealer.server(Crypto::ServerKey.new(Crypto.random_key))
    system.pg_dump_sealed("partiduo_garde", File.join(root, "b.dump.enc"), sealer)
    streams.last.should eq(helper + ["dump", "partiduo_garde", "-"])
    File.read(File.join(root, "b.dump.enc")).starts_with?("PDUOBAK").should be_true
    system.dump_argv("partiduo_garde").should eq(helper + ["dump", "partiduo_garde", "-"])
    system.restore_argv("partiduo_garde").should eq(helper + ["restore", "partiduo_garde", "-"])
    system.media_archive_argv("garde", "/x", File.join(root, "b.files")).should eq(helper + ["media-archive", "garde", File.join(root, "b.files"), "-"])
    system.media_restore_argv("garde").should eq(helper + ["media-restore", "garde", "-"])
    expect_raises(PartiduoAgent::StepError, /hors du répertoire/) { system.media_archive_argv("garde", "/x", "/etc/liste") }
  end
end

# Production enregistrée : les flux ne lancent rien.
private class StreamRecordingProduction < PartiduoAgent::ProductionSystem
  def initialize(config : PartiduoAgent::Config, log : Proc(String, Nil), @streams : Array(Array(String)))
    super(config, log)
  end

  def run_stream(argv : Array(String), env = {} of String => String, input : IO? = nil, output : IO? = nil) : {Int32, String}
    @streams << argv
    {0, ""}
  end
end
