# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Chiffrement des sauvegardes réglé dans l'administration (D-CHF-001 à
# D-CHF-012) : réglage du cabinet et du dossier, dépôt de la clé publique,
# paramètres des tâches, sauvegardes enregistrées avec leur mode, clé de
# données remise une seule fois, écrans et journal d'audit.

private alias Crypto = PartiduoAdmin::BackupCrypto
private alias Config = PartiduoAdmin::Config

private def api(path : String, token : String, body = {} of String => String) : JSON::Any
  headers = {"Content-Type" => "application/json", "Host" => "127.0.0.1", "Authorization" => "Bearer #{token}"}
  JSON.parse(Marten::Spec::Client.new.post(path, data: body.to_json, content_type: "application/json", headers: headers).content)
end

private def audits(action : String) : Array(PartiduoAdmin::AuditEntry)
  PartiduoAdmin::AuditEntry.filter(action: action).order("id").to_a
end

# Cabinet avec clé déposée par son admin : {cabinet, admin, clé publique}.
private def keyed_firm(name : String) : {PartiduoAdmin::Firm, PartiduoAdmin::User, Crypto::PublicKey}
  firm = AdminSpec.firm(name)
  admin = AdminSpec.user(Config::FIRM_ADMIN, firm)
  pair = AdminSpec::Keys.pair("a")
  PartiduoAdmin::BackupEncryption.deposit_key(admin, firm, pair.public_pem).ok?.should be_true
  {firm.reload, admin, Crypto::PublicKey.new(pair.public_pem)}
end

# Sauvegarde « clé du cabinet » telle que l'exécutant la rendrait.
private def cabinet_backup(dossier : PartiduoAdmin::Dossier, key : Crypto::PublicKey) : {PartiduoAdmin::Backup, Crypto::Sealer}
  sealer = Crypto::Sealer.cabinet(key)
  data = JSON.parse({"path" => "/var/backups/partiduo/#{dossier.slug}/backup-20260927T100000Z.dump.enc",
                     "media_path" => "/var/backups/partiduo/#{dossier.slug}/backup-20260927T100000Z.media.tar.gz.enc",
                     "sha256" => "a" * 64, "media_sha256" => "b" * 64, "size_bytes" => 10,
                     "taken_at" => (SPEC_NOW - 1.day).to_rfc3339, "encryption" => sealer.describe}.to_json)
  task = PartiduoAdmin::Task.create!(kind: "backup.run", server: dossier.server!, dossier: dossier, params: %({"kind":"manual"}))
  {PartiduoAdmin::Tasks::Effects.record_backup(task, dossier, "manual", data, SPEC_NOW), sealer}
end

describe "Chiffrement des sauvegardes : réglages (D-CHF-001, D-CHF-008)" do
  it "chiffre par défaut par la clé du serveur, et le dossier peut surcharger le cabinet" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    dossier.effective_encryption.should eq("server")
    task = PartiduoAdmin::Fleet.backup_now(nil, dossier).value!
    task.params_json["encryption"]["mode"].should eq("server")

    admin = AdminSpec.user(Config::FIRM_ADMIN, firm)
    PartiduoAdmin::BackupEncryption.set_dossier_mode(admin, dossier, "none").ok?.should be_true
    dossier.reload.effective_encryption.should eq("none")
    PartiduoAdmin::Fleet.backup_now(nil, dossier, "scheduled").value!.params_json["encryption"]["mode"].should eq("none")
    audits("backup_encryption.dossier").last.detail.to_s.should contain(%("to":"none"))
    PartiduoAdmin::BackupEncryption.set_dossier_mode(admin, dossier, "").ok?.should be_true
    dossier.reload.effective_encryption.should eq("server")
  end

  it "exige une clé déposée pour « clé du cabinet » et la transmet avec son empreinte" do
    firm = AdminSpec.firm
    admin = AdminSpec.user(Config::FIRM_ADMIN, firm)
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    refused = PartiduoAdmin::BackupEncryption.set_firm_mode(admin, firm, "cabinet")
    refused.errors["mode"].should eq(["admin.errors.encryption.no_key"])
    PartiduoAdmin::BackupEncryption.set_dossier_mode(admin, dossier, "cabinet").ok?.should be_false

    pair = AdminSpec::Keys.pair("a")
    PartiduoAdmin::BackupEncryption.deposit_key(admin, firm, "pas une clé").errors["public_key"]
      .should eq(["admin.errors.encryption.public_key"])
    PartiduoAdmin::BackupEncryption.deposit_key(admin, firm, AdminSpec::Keys.pair("petite", 2048).public_pem).ok?.should be_false
    PartiduoAdmin::BackupEncryption.deposit_key(admin, firm, pair.public_pem).ok?.should be_true
    fingerprint = Crypto::PublicKey.new(pair.public_pem).fingerprint
    firm.reload.backup_key_fingerprint.should eq(fingerprint)
    deposit = audits("backup_key.deposit").last
    deposit.actor_label.should eq(admin.email)
    deposit.detail.to_s.should contain(fingerprint)

    PartiduoAdmin::BackupEncryption.set_firm_mode(admin, firm, "cabinet").ok?.should be_true
    audits("backup_encryption.firm").last.detail.to_s.should contain(%("to":"cabinet"))
    params = PartiduoAdmin::Fleet.backup_now(nil, dossier.reload).value!.params_json["encryption"]
    params["mode"].should eq("cabinet")
    params["key_fingerprint"].should eq(fingerprint)
    Crypto::PublicKey.new(params["public_key"].as_s).fingerprint.should eq(fingerprint)
    # Archivage et montée de version : sauvegardes chiffrées de même.
    PartiduoAdmin::Fleet.lifecycle(admin, dossier, "archive", "fin").value!.params_json["encryption"]["mode"].should eq("cabinet")
  end

  it "réserve le dépôt de la clé et la sortie du mode « clé du cabinet » à l'admin du cabinet" do
    firm, admin, _ = keyed_firm("Clé réservée")
    root = AdminSpec.super_admin
    other = AdminSpec.user(Config::FIRM_ADMIN, AdminSpec.firm)
    manager = AdminSpec.user(Config::FILE_MANAGER, firm)
    PartiduoAdmin::BackupEncryption.deposit_key(root, firm, AdminSpec::Keys.pair("b").public_pem).errors.has_key?("base").should be_true
    PartiduoAdmin::BackupEncryption.set_firm_mode(other, firm, "none").errors.has_key?("base").should be_true
    PartiduoAdmin::BackupEncryption.set_firm_mode(manager, firm, "none").errors.has_key?("base").should be_true

    PartiduoAdmin::BackupEncryption.set_firm_mode(root, firm, "cabinet").ok?.should be_true
    # Le super-admin (l'exploitant) ne rend pas lisibles les sauvegardes suivantes.
    PartiduoAdmin::BackupEncryption.set_firm_mode(root, firm, "server").errors["mode"]
      .should eq(["admin.errors.encryption.leave_cabinet"])
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    PartiduoAdmin::BackupEncryption.set_dossier_mode(root, dossier, "none").errors["mode"]
      .should eq(["admin.errors.encryption.leave_cabinet"])
    PartiduoAdmin::BackupEncryption.set_firm_mode(admin, firm, "server").ok?.should be_true
  end

  it "garde à chaque sauvegarde son mode quand le réglage change" do
    firm, admin, key = keyed_firm("Modes figés")
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    old = AdminSpec.backup(dossier, SPEC_NOW - 3.days)
    backup, _ = cabinet_backup(dossier, key)
    PartiduoAdmin::BackupEncryption.set_firm_mode(admin, firm, "cabinet").ok?.should be_true
    PartiduoAdmin::BackupEncryption.set_firm_mode(admin, firm, "none").ok?.should be_true
    old.reload.encryption_mode.should eq("none")
    backup.reload.encryption_mode.should eq("cabinet")
    backup.key_fingerprint.should eq(key.fingerprint)
    backup.wrapped_key.to_s.should_not be_empty
    backup.media_sha256.should eq("b" * 64)
  end
end

describe "Chiffrement des sauvegardes : restauration et restauration test (D-CHF-005, D-CHF-007)" do
  it "n'accepte que la bonne clé de données, la remet une seule fois à l'exécutant et ne la garde nulle part" do
    firm, admin, key = keyed_firm("Restauration")
    server, token = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    backup, sealer = cabinet_backup(dossier, key)
    date = SPEC_NOW

    missing = PartiduoAdmin::Fleet.restore(admin, dossier, date, "replace")
    missing.errors["data_key"].should eq(["admin.errors.encryption.key_required"])
    wrong = PartiduoAdmin::Fleet.restore(admin, dossier, date, "replace", "", backup.pk!.as(Int64), Base64.strict_encode(Crypto.random_key))
    wrong.errors["data_key"].should eq(["admin.errors.encryption.wrong_key"])
    PartiduoAdmin::Task.filter(kind: "backup.restore").count.should eq(0)

    data_key = Base64.strict_encode(sealer.data_key)
    task = PartiduoAdmin::Fleet.restore(admin, dossier, date, "replace", "", backup.pk!.as(Int64), data_key).value!
    task.params.to_s.should_not contain(data_key)
    task.params_json["key_provided"].as_bool.should be_true
    task.params_json["backup_encryption"]["commitment"].should eq(sealer.commitment.hexstring)
    task.params_json["encryption"]["mode"].should eq("server")
    PartiduoAdmin::AuditEntry.all.to_a.none?(&.detail.to_s.includes?(data_key)).should be_true
    audits("backup.restore").last.detail.to_s.should contain(%("key_provided":"true"))

    # Tâches précédentes du dossier remises d'abord ; puis la restauration.
    claimed = api("/api/agent/v1/claim", token)
    until claimed["task"]["kind"] == "backup.restore"
      claimed = api("/api/agent/v1/claim", token)
    end
    claimed["task"]["secrets"]["data_keys"].as_a.map(&.as_s).should eq([data_key])
    claimed["task"]["params"].to_json.should_not contain(data_key)
    task.reload.data_keys.should eq("")
    # Bail échu : la tâche est reprise, sans la clé.
    task.lease_until = SPEC_NOW - 1.minute
    task.save!
    again = api("/api/agent/v1/claim", token)
    again["task"]["id"].should eq(task.pk)
    again["task"]["secrets"]["data_keys"].as_a.should be_empty
    api("/api/agent/v1/tasks/#{task.pk}/finish", token, {"ok" => false, "error" => "clé du cabinet requise", "result" => {} of String => String})
    # Une tâche qui a reçu la clé ne se rejoue pas : la clé est à refournir.
    PartiduoAdmin::Tasks.retryable?(task.reload).should be_false
  end

  it "vérifie l'enveloppe seule sans la clé, en entier avec elle" do
    firm, admin, key = keyed_firm("Tests")
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    backup, sealer = cabinet_backup(dossier, key)
    envelope = PartiduoAdmin::Fleet.test_restore(nil, backup).value!
    envelope.params_json["backup_encryption"]["mode"].should eq("cabinet")
    envelope.params_json["media_sha256"].should eq("b" * 64)
    envelope.data_keys.should eq("")
    envelope.state = "running"
    envelope.save!
    PartiduoAdmin::Tasks.finish(envelope, true, JSON.parse(%({"verified":false,"envelope_verified":true,"check":"envelope"})))
    backup.reload.test_check.should eq("envelope")
    backup.state.should eq("done")
    backup.test_restored_at.should_not be_nil

    PartiduoAdmin::Fleet.test_restore(admin, backup, Base64.strict_encode(Crypto.random_key)).ok?.should be_false
    full = PartiduoAdmin::Fleet.test_restore(admin, backup, Base64.strict_encode(sealer.data_key)).value!
    full.data_keys.to_s.should_not be_empty
    full.state = "running"
    full.save!
    PartiduoAdmin::Tasks.finish(full, true, JSON.parse(%({"verified":true,"check":"full"})))
    full.reload.data_keys.should eq("")
    backup.reload.test_check.should eq("full")
    backup.state.should eq("verified")
  end

  it "enregistre le mode, l'empreinte et la clé de données enveloppée que rend l'exécutant" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    task = PartiduoAdmin::Fleet.backup_now(nil, dossier).value!
    api("/api/agent/v1/claim", token)
    result = {"path" => "/var/backups/partiduo/#{dossier.slug}/b.dump.enc", "media_path" => "", "size_bytes" => 1,
              "sha256" => "c" * 64, "media_sha256" => "d" * 64, "taken_at" => SPEC_NOW.to_rfc3339,
              "encryption" => {"format" => 1, "mode" => "server", "key_fingerprint" => "e" * 64, "commitment" => "f" * 64,
                               "wrapped_key" => "AAAA"}}
    api("/api/agent/v1/tasks/#{task.pk}/finish", token, {"ok" => true, "result" => result})
    backup = PartiduoAdmin::Backup.filter(dossier_id: dossier.pk).first!
    backup.encryption_mode.should eq("server")
    backup.key_fingerprint.should eq("e" * 64)
    backup.key_commitment.should eq("f" * 64)
    # Clé du serveur : l'administration ne garde pas sa clé enveloppée.
    backup.wrapped_key.should eq("")
    backup.media_sha256.should eq("d" * 64)
  end
end

describe "Chiffrement des sauvegardes : écrans (D-CHF-002, D-CHF-005)" do
  it "règle le cabinet, dépose la clé et affiche son empreinte, en français, anglais et néerlandais" do
    firm = AdminSpec.firm("Écrans")
    admin = AdminSpec.user(Config::FIRM_ADMIN, firm)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(admin))
    page = browser.get("/firms/#{firm.pk}/backups")
    page.status.should eq(200)
    html = page.html
    html.should contain("Chiffrement des sauvegardes")
    html.should contain(%(name="mode" value="cabinet" disabled))
    html.should contain("data-pd-keygen")
    html.should contain(%(<script src="/assets/admin/js/backup-keys.js"))
    # Champs de la phrase de passe sans attribut name : jamais envoyés.
    html.should_not match(/<input[^>]*name="[^"]*"[^>]*id="pd-keygen-pass"/)
    browser.get("/dossiers").html.should contain(%(href="/firms/#{firm.pk}/backups"))

    pair = AdminSpec::Keys.pair("a")
    browser.post("/firms/#{firm.pk}/backups/key", {"public_key" => "n'importe quoi"}).status.should eq(422)
    deposited = browser.post("/firms/#{firm.pk}/backups/key", {"public_key" => pair.public_pem})
    deposited.status.should eq(302)
    fingerprint = Crypto::PublicKey.new(pair.public_pem).fingerprint
    browser.get("/firms/#{firm.pk}/backups").html.should contain(Crypto.display_fingerprint(fingerprint))
    browser.post("/firms/#{firm.pk}/backups", {"mode" => "cabinet"}).status.should eq(302)
    firm.reload.backup_encryption.should eq("cabinet")

    {"en" => "Backup encryption", "nl" => "Versleuteling van back-ups"}.each do |locale, title|
      admin.locale = locale
      admin.save!
      browser.get("/firms/#{firm.pk}/backups").html.should contain(title)
    end
  end

  it "refuse la page d'un autre cabinet et du gestionnaire ; le super-admin voit sans pouvoir déposer" do
    firm = AdminSpec.firm
    other = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(Config::FIRM_ADMIN, AdminSpec.firm)))
    other.get("/firms/#{firm.pk}/backups").status.should eq(403)
    manager = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(Config::FILE_MANAGER, firm)))
    manager.get("/firms/#{firm.pk}/backups").status.should eq(403)
    root = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.super_admin))
    page = root.get("/firms/#{firm.pk}/backups").html
    page.should contain("Seul l'admin du cabinet")
    page.should_not contain("data-pd-keygen")
    root.post("/firms/#{firm.pk}/backups/key", {"public_key" => AdminSpec::Keys.pair("a").public_pem}).status.should eq(403)
    root.get("/firms").html.should contain(%(href="/firms/#{firm.pk}/backups"))
  end

  it "affiche le mode de chaque sauvegarde et demande la clé du cabinet avant de restaurer" do
    firm, admin, key = keyed_firm("Fiche")
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    AdminSpec.backup(dossier, SPEC_NOW - 5.days)
    backup, sealer = cabinet_backup(dossier, key)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(admin))
    fiche = browser.get("/dossiers/#{dossier.pk}").html
    fiche.should contain("Clé du cabinet")
    fiche.should contain(backup.short_fingerprint)
    fiche.should contain(%(href="/backups/#{backup.pk}/unlock?purpose=test"))
    fiche.should contain(%(action="/dossiers/#{dossier.pk}/encryption"))

    redirect = browser.post("/dossiers/#{dossier.pk}/restore", {"date" => SPEC_NOW.to_s("%F"), "target" => "replace", "new_slug" => ""})
    redirect.status.should eq(302)
    location = redirect.headers["Location"]
    location.should start_with("/backups/#{backup.pk}/unlock?purpose=restore")
    unlock = browser.get(location)
    unlock.status.should eq(200)
    html = unlock.html
    html.should contain(%(data-wrapped="#{backup.wrapped_key}"))
    html.should contain(%(data-fingerprint="#{key.fingerprint}"))
    html.should contain(%(name="data_key"))
    html.should contain(%(name="backup_id" value="#{backup.pk}"))
    # Clé privée et phrase de passe : aucun champ nommé, rien n'est envoyé.
    html.scan(/<(?:input|textarea)[^>]*>/).map(&.[0]).select(&.includes?("data-pd-key")).each do |tag|
      tag.should_not contain("name=")
    end

    browser.post("/dossiers/#{dossier.pk}/restore", {"date" => SPEC_NOW.to_s("%F"), "target" => "replace", "new_slug" => "",
                                                     "backup_id" => backup.pk.to_s, "data_key" => Base64.strict_encode(Crypto.random_key)})
    PartiduoAdmin::Task.filter(kind: "backup.restore").count.should eq(0)
    done = browser.post("/dossiers/#{dossier.pk}/restore", {"date" => SPEC_NOW.to_s("%F"), "target" => "replace", "new_slug" => "",
                                                            "backup_id" => backup.pk.to_s, "data_key" => Base64.strict_encode(sealer.data_key)})
    done.status.should eq(302)
    PartiduoAdmin::Task.filter(kind: "backup.restore").count.should eq(1)

    tested = browser.post("/backups/#{backup.pk}/test", {"data_key" => Base64.strict_encode(sealer.data_key)})
    tested.status.should eq(302)
    PartiduoAdmin::Task.filter(kind: "backup.test_restore").first!.data_keys.to_s.should_not be_empty
    browser.get("/backups/#{backup.pk}/unlock?purpose=test").status.should eq(200)
  end
end
