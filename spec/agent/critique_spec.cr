# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Critique de complétude du lot A (ADR-008 D3, D4) : une tâche forgée par
# une administration compromise ne donne accès ni aux données d'un autre
# dossier ni au lien d'invitation, et ne fait rien exécuter d'autre que la
# liste fermée (D-CRA-001 à D-CRA-005).

private APP_ROOT = File.expand_path("../..", __DIR__)

private def params(slug = "garde", **extra) : Hash(String, JSON::Any)
  base = JSON.parse({"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost",
                     "database" => "", "modules" => ["accounting", "invoicing"], "extensions" => [] of String,
                     "package" => "app", "locale" => "nl"}.to_json).as_h
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

describe "partiduo-agent : sauvegardes d'un autre dossier (D-CRA-001)" do
  it "refuse de restaurer, relire ou effacer une sauvegarde qui n'est pas celle du dossier" do
    with_admin do |admin|
      config = admin.config
      other = File.join(config.backup_dir, "voisin", "backup-20260901T000000Z.dump")
      cases = [
        {"backup.restore", params(path: other, target: "replace")},
        {"backup.restore", params(path: other, target: "new", new_slug: "copie")},
        {"backup.restore", params(path: File.join(config.backup_dir, "garde", "b.dump"),
          media_path: File.join(config.backup_dir, "voisin", "m.tar.gz"), target: "replace")},
        {"backup.test_restore", params(path: other)},
        {"instance.restore_archive", params(path: other)},
        {"backup.prune", params(paths: [other])},
        {"instance.delete", params(backups: [other], approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"])},
        # Préfixe trompeur : « garde-2 » n'est pas « garde ».
        {"backup.prune", params(paths: [File.join(config.backup_dir, "garde-2", "b.dump")])},
        {"backup.prune", params(paths: [File.join(config.backup_dir, "garde", "..", "voisin", "b.dump")])},
      ]
      cases.each_with_index do |(kind, task_params), index|
        report, dry = run_dry(admin, 700_i64 + index, kind, task_params, admin.config,
          databases: ["partiduo_adm_garde"])
        report["ok"].as_bool.should be_false
        report["error"].as_s.should contain("du dossier")
        dry.calls.none? { |call| call.starts_with?("pg_restore") || call.starts_with?("rm") || call.starts_with?("dropdb") }
          .should be_true
      end
    end
  end

  it "accepte la sauvegarde du dossier lui-même" do
    with_admin do |admin|
      config = admin.config
      own = File.join(config.backup_dir, "garde", "backup-20260901T000000Z.dump")
      report, dry = run_dry(admin, 720_i64, "backup.prune", params(paths: [own]), config)
      report["ok"].as_bool.should be_true
      dry.calls.should contain("rm #{own}")
    end
  end
end

describe "partiduo-agent : arguments de l'interface d'instance (D-CRA-002)" do
  it "refuse une adresse ou un motif qui serait pris pour une option" do
    with_admin do |admin|
      [
        params(email: "--list-file=/tmp/x", reason: "r", approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"]),
        params(email: "a@x.fr", reason: "--terminate-sessions", approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"]),
        params(email: "a@x.fr", reason: "r\nx", approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"]),
        params(email: "a@x.fr", reason: "r", approval_ref: "DV-1", approvers: ["--x", "b@x.fr"]),
      ].each_with_index do |task_params, index|
        report, dry = run_dry(admin, 730_i64 + index, "instance.admin_invite", task_params,
          databases: ["partiduo_adm_garde"])
        report["ok"].as_bool.should be_false
        report["error"].as_s.should contain("valeur refusée")
        dry.calls.none?(&.starts_with?("instance admin-invite")).should be_true
      end
    end
  end
end

describe "partiduo-agent : invitation remise par le serveur (D-CRA-003)" do
  it "remet le lien du recours d'accès sans le rendre à l'administration" do
    with_admin do |admin|
      config = admin.config
      config.mail_command = "/usr/sbin/sendmail -oi"
      config.mail_from = "noreply@partiduo.localhost"
      report, dry = run_dry(admin, 740_i64, "instance.admin_invite",
        params(email: "gerant@demo.fr", reason: "gérant parti", approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"]),
        config, databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      report.to_json.should_not contain("invitation/")
      report["result"]["invitation_delivered"].as_s.should eq("server")
      admin.logs[740_i64].join('\n').should_not contain("invitation/")
      dry.mails.size.should eq(1)
      recipient, message = dry.mails.first
      recipient.should eq("gerant@demo.fr")
      message.should contain("To: gerant@demo.fr\r\n")
      body = Base64.decode_string(message.split("\r\n\r\n", 2)[1].gsub("\r\n", ""))
      body.should contain("https://dry-run/invitation/DRYRUN")
      body.should contain("Partiduo-dossier garde.partiduo.localhost") # langue du dossier (nl)
    end
  end

  it "remet le lien de création sans le rendre à l'administration" do
    with_admin do |admin|
      config = admin.config
      config.mail_command = "/usr/sbin/sendmail -oi"
      config.mail_from = "noreply@partiduo.localhost"
      report, dry = run_dry(admin, 741_i64, "instance.create",
        params(name: "Garde", regime: "fr", admin_email: "patron@garde.fr", siren: "", vat: ""), config)
      report["ok"].as_bool.should be_true
      report.to_json.should_not contain("DRYRUNTOKEN")
      report["result"]["invitation_delivered"].as_s.should eq("server")
      dry.mails.map(&.[0]).should eq(["patron@garde.fr"])
    end
  end

  it "sans commande de courriel, rend le lien à l'administration (D-ADM-009)" do
    with_admin do |admin|
      report, dry = run_dry(admin, 742_i64, "instance.admin_invite",
        params(email: "gerant@demo.fr", reason: "r", approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"]),
        databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_true
      report["result"]["url"].as_s.should contain("invitation")
      dry.mails.should be_empty
    end
  end

  it "envoie par la commande configurée, sans shell, le destinataire en dernier argument" do
    dir = File.join(Dir.tempdir, "partiduo-mail-#{Random::Secure.hex(4)}")
    Dir.mkdir_p(dir)
    script = File.join(dir, "sendmail")
    File.write(script, "#!/bin/sh\nprintf '%s\\n' \"$@\" > #{dir}/argv\ncat > #{dir}/message\n", perm: 0o755)
    config = PartiduoAgent::Config.new
    config.mode = PartiduoAgent::Mode::Local
    config.mail_command = "#{script} -oi"
    config.mail_from = "noreply@partiduo.localhost"
    system = PartiduoAgent::LocalSystem.new(config, ->(_line : String) { nil })
    system.deliver_invitation("patron@garde.fr", "garde.partiduo.localhost", "https://garde.partiduo.localhost/invitation/abc", "fr")
    File.read_lines(File.join(dir, "argv")).should eq(["-oi", "patron@garde.fr"])
    File.read(File.join(dir, "message")).should contain("Subject: =?UTF-8?B?")
    expect_raises(PartiduoAgent::StepError, /adresse/) do
      system.deliver_invitation("-oQ/tmp@x.fr", "garde.partiduo.localhost", "https://x/invitation/abc", "fr")
    end
    expect_raises(PartiduoAgent::StepError, /adresse/) do
      system.deliver_invitation("a@x.fr\r\nBcc: z@y.fr", "garde.partiduo.localhost", "https://x/invitation/abc", "fr")
    end
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  it "exige un expéditeur avec une commande de courriel" do
    ENV["PARTIDUO_AGENT_TOKEN"] = "jeton"
    expect_raises(ArgumentError, /--mail-from/) do
      PartiduoAgent::Config.parse(["--mode", "dry-run", "--mail-command", "/usr/sbin/sendmail"])
    end
  ensure
    ENV.delete("PARTIDUO_AGENT_TOKEN")
  end
end

describe "partiduo-agent : liste des pièces jointes (D-CRA-004)" do
  it "écarte les chemins hors du stockage de l'instance" do
    PartiduoAgent::System.safe_media_line?("attachments/2026/09/a.pdf").should be_true
    ["/etc/partiduo/voisin.env", "../voisin/media/a.pdf", "attachments/../../x", "-T", "a//b", "a\tb", ""].each do |line|
      PartiduoAgent::System.safe_media_line?(line).should be_false
    end
  end

  it "l'enveloppe refuse une liste qui sort du stockage" do
    dir = File.join(Dir.tempdir, "partiduo-helpers-#{Random::Secure.hex(4)}")
    Dir.mkdir_p(File.join(dir, "opt", "instances", "demo", "media"))
    Dir.mkdir_p(File.join(dir, "backups", "demo"))
    File.write(File.join(dir, "opt", "instances", "demo", "media", "a.pdf"), "pdf")
    conf = File.join(dir, "helpers.conf")
    File.write(conf, "DOMAIN=partiduo.test\nINSTALL_ROOT=#{dir}/opt\nBACKUP_DIR=#{dir}/backups\nPG_SOCKET=/tmp\n")
    list = File.join(dir, "backups", "demo", "x.files")
    archive = File.join(dir, "backups", "demo", "x.tar.gz")
    env = {"PARTIDUO_AGENT_HELPERS_CONF" => conf, "SUDO_USER" => nil} of String => String?
    helper = File.join(APP_ROOT, "deploy", "libexec", "partiduo-agent-instance")
    ["../../../helpers.conf\n", "/etc/hosts\n", "a.pdf\n../x\n"].each do |content|
      File.write(list, content)
      stderr = IO::Memory.new
      status = Process.run(helper, ["media-archive", "demo", list, archive], env: env, error: stderr)
      status.exit_code.should eq(2)
      stderr.to_s.should contain("liste refusée")
      File.exists?(archive).should be_false
    end
    # Liste sûre : acceptée par le contrôle (l'archive elle-même demande le
    # tar GNU du serveur, `--ignore-failed-read`, absent de bsdtar).
    File.write(list, "a.pdf\n")
    stderr = IO::Memory.new
    Process.run(helper, ["media-archive", "demo", list, archive], env: env, error: stderr)
    stderr.to_s.should_not contain("liste refusée")
  ensure
    FileUtils.rm_rf(dir) if dir
  end
end

describe "partiduo-agent : erreurs des outils PostgreSQL (D-CRA-005)" do
  it "ne renvoie pas à l'administration les valeurs citées par PostgreSQL" do
    text = "pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint \"x\"\n" \
           "DETAIL:  Key (label)=(Salaire de Jeanne) already exists.\n" \
           "Command was: COPY public.entry (id, label) FROM stdin;\n"
    redacted = PartiduoAgent::System.redact_errors(text)
    redacted.should contain("duplicate key value")
    redacted.should_not contain("Jeanne")
    redacted.should_not contain("COPY")
  end
end

describe "partiduo-agent : durée légale revérifiée par le serveur (D-CRA-007)" do
  it "refuse une suppression définitive sans archive, ou avant dix ans" do
    with_admin do |admin|
      config = admin.config
      delete = params(approval_ref: "DV-1", approvers: ["a@x.fr", "b@x.fr"], backups: [] of String)
      report, dry = run_dry(admin, 750_i64, "instance.delete", delete, config, databases: ["partiduo_adm_garde"])
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("aucune archive")
      dry.calls.none? { |call| call.starts_with?("retrait") || call.starts_with?("dropdb") }.should be_true

      recent = File.join(config.backup_dir, "garde", "archive-#{(Time.utc - 2.years).to_s("%Y%m%dT%H%M%SZ")}.dump")
      admin.push(751_i64, "instance.delete", delete)
      runner = PartiduoAgent::Runner.new(config)
      system = runner.build_system(->(_line : String) { nil }).as(PartiduoAgent::DrySystem)
      system.files[File.join(config.backup_dir, "garde", "archive-20100101T000000Z.dump")] = 1_i64
      system.files[recent] = 1_i64
      runner.run_once.should be_true
      admin.finished[751_i64]["ok"].as_bool.should be_false
      admin.finished[751_i64]["error"].as_s.should contain("durée légale")
      system.calls.none?(&.starts_with?("dropdb")).should be_true
    end
  end

  it "refuse d'effacer une archive dans sa durée légale" do
    with_admin do |admin|
      config = admin.config
      recent = File.join(config.backup_dir, "garde", "archive-#{(Time.utc - 1.year).to_s("%Y%m%dT%H%M%SZ")}.media.tar.gz")
      report, dry = run_dry(admin, 752_i64, "backup.prune", params(paths: [recent]), config)
      report["ok"].as_bool.should be_false
      report["error"].as_s.should contain("durée légale")
      dry.calls.none?(&.starts_with?("rm")).should be_true
      old = File.join(config.backup_dir, "garde", "archive-20150101T000000Z.dump")
      run_dry(admin, 753_i64, "backup.prune", params(paths: [old]), config)[0]["ok"].as_bool.should be_true
    end
  end
end
