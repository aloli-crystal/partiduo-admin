# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Règles et cas limites de l'administration du parc (ADR-008) qui
# complètent les specs des modèles, des droits et des actions : contraintes
# en base, référentiels, double validation, vagues, planification,
# supervision, API de l'exécutant.

private def finish_task(task : PartiduoAdmin::Task, ok = true, result = {} of String => String)
  task.state = "running"
  task.save!
  PartiduoAdmin::Tasks.finish(task, ok, JSON.parse(result.to_json), ok ? "" : "échec", Array(String).new, SPEC_NOW)
  task.reload
end

private def agent_call(path : String, token : String?, body = "{}") : Marten::HTTP::Response
  headers = {"Content-Type" => "application/json", "Host" => "127.0.0.1"}
  headers["Authorization"] = "Bearer #{token}" if token
  Marten::Spec::Client.new.post(path, data: body, content_type: "application/json", headers: headers)
end

private def sql_exec(sql : String) : Nil
  Marten::DB::Connection.default.open(&.exec(sql))
end

private def dossier_input(firm, server, payer, slug = "regle-a") : PartiduoAdmin::Fleet::DossierInput
  PartiduoAdmin::Fleet::DossierInput.new(slug: slug, label: "Règle SARL", regime: "fr", admin_email: "patron@regle.fr",
    server_id: PartiduoAdmin.id?(server.pk), firm_id: PartiduoAdmin.id?(firm.pk), payer_id: PartiduoAdmin.id?(payer.pk))
end

describe "Contraintes en base de l'administration" do
  it "refuse en SQL toute modification ou suppression du journal d'audit, et accepte l'ajout" do
    entry = PartiduoAdmin::Audit.log(nil, "spec.sql", actor_label: "spec")
    expect_raises(Exception, /ajout seul/) { sql_exec("UPDATE admin_audit_entry SET outcome = 'fail' WHERE id = #{entry.pk}") }
    expect_raises(Exception, /ajout seul/) { sql_exec("DELETE FROM admin_audit_entry") }
    sql_exec("INSERT INTO admin_audit_entry (actor_label, action, target_type, target_label, outcome, ip, detail, created_at) " \
             "VALUES ('psql', 'spec.insert', '', '', 'ok', '', '{}', now())")
    PartiduoAdmin::AuditEntry.filter(action: "spec.insert").count.should eq(1)
  end

  it "rend uniques un sous-domaine de dossier, une affectation et une référence de double validation" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, slug: "unique")
    expect_raises(Exception) { AdminSpec.dossier(firm, server, slug: "unique") }
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    expect_raises(Exception) { PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier) }
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Approval.create!(kind: "admin_invite", reference: "DV-AAAA-AAAA", dossier: dossier, reason: "motif",
      requested_by: requester, expires_at: SPEC_NOW + 1.day)
    expect_raises(Exception) do
      PartiduoAdmin::Approval.create!(kind: "admin_invite", reference: "DV-AAAA-AAAA", dossier: dossier, reason: "motif",
        requested_by: requester, expires_at: SPEC_NOW + 1.day)
    end
  end

  it "protège cabinet, serveur et donneur d'ordre d'un dossier contre la suppression" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    expect_raises(Exception) { firm.delete }
    expect_raises(Exception) { server.delete }
    expect_raises(Exception) { dossier.payer!.delete }
    PartiduoAdmin::Dossier.filter(id: dossier.pk).exists?.should be_true
  end

  it "ne conserve le jeton d'un serveur qu'en empreinte, et le renouvellement invalide l'ancien" do
    server, token = AdminSpec.server
    server.token_digest.should_not eq(token)
    server.token_digest.should eq(PartiduoAdmin::Secrets.digest(token))
    fresh = PartiduoAdmin::Directory.rotate_token(AdminSpec.super_admin, server) || fail("jeton non renouvelé")
    agent_call("/api/agent/v1/claim", token).status.should eq(401)
    agent_call("/api/agent/v1/claim", fresh).status.should eq(200)
    PartiduoAdmin::Directory.rotate_token(AdminSpec.user, server).should be_nil
  end
end

describe "Protocole : sous-domaines réservés" do
  it "refuse les sous-domaines de l'administration et ceux des bases de restauration test" do
    %w[admin www rt-demo-5].each do |slug|
      PartiduoAdmin::Protocol.valid_slug?(slug).should be_false
    end
    %w[administration demo-rt art-deco].each do |slug|
      PartiduoAdmin::Protocol.valid_slug?(slug).should be_true
    end
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    outcome = PartiduoAdmin::Fleet.create_dossier(AdminSpec.super_admin, dossier_input(firm, server, AdminSpec.payer(firm), "admin"))
    outcome.errors["slug"].should eq(["admin.errors.dossier.slug"])
  end

  it "n'accepte pour un dossier qu'une version publiée, jamais une valeur libre" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    payer = AdminSpec.payer(firm)
    root = AdminSpec.super_admin
    base = dossier_input(firm, server, payer, "version-libre")
    trap = PartiduoAdmin::Fleet::DossierInput.new(slug: base.slug, label: base.label, regime: base.regime, admin_email: base.admin_email,
      server_id: base.server_id, firm_id: base.firm_id, payer_id: base.payer_id, version: "../../../tmp/piege")
    PartiduoAdmin::Fleet.create_dossier(root, trap).errors["version"].should eq(["admin.errors.invalid"])
    PartiduoAdmin::Protocol.valid_version?("0.2.0/../x").should be_false
    PartiduoAdmin::Protocol.valid_version?("0.2.0-rc.1").should be_true
    PartiduoAdmin::Release.create!(version: "0.2.0")
    ok = PartiduoAdmin::Fleet::DossierInput.new(slug: base.slug, label: base.label, regime: base.regime, admin_email: base.admin_email,
      server_id: base.server_id, firm_id: base.firm_id, payer_id: base.payer_id, version: "0.2.0")
    PartiduoAdmin::Fleet.create_dossier(root, ok).value!.version.should eq("0.2.0")
  end
end

describe "Référentiels de l'administration" do
  it "invite un utilisateur dans le cabinet de l'admin qui l'invite, sans rôle au-dessus du sien" do
    north = AdminSpec.firm("Nord")
    south = AdminSpec.firm("Sud")
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    input = PartiduoAdmin::Directory::UserInput.new(email: " Nouvelle@Cabinet.FR ", role: PartiduoAdmin::Config::FILE_MANAGER,
      firm_id: PartiduoAdmin.id?(south.pk))
    user = PartiduoAdmin::Directory.invite_user(admin, input).value!
    user.email.should eq("nouvelle@cabinet.fr")
    user.firm_id.should eq(north.pk)
    user.password_digest.should be_nil
    PartiduoAdmin::Invitation.filter(user_id: user.pk).count.should eq(1)

    PartiduoAdmin::Directory.invite_user(admin, input).errors["email"].should eq(["admin.errors.user.email_taken"])
    root = PartiduoAdmin::Directory::UserInput.new(email: "root@cabinet.fr", role: PartiduoAdmin::Config::SUPER_ADMIN)
    PartiduoAdmin::Directory.invite_user(admin, root).errors["role"].should eq(["admin.errors.forbidden"])
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, north)
    other = PartiduoAdmin::Directory::UserInput.new(email: "autre@cabinet.fr", role: PartiduoAdmin::Config::FILE_MANAGER)
    PartiduoAdmin::Directory.invite_user(manager, other).errors["role"].should eq(["admin.errors.forbidden"])
    bad = PartiduoAdmin::Directory::UserInput.new(email: "pas-une-adresse", role: PartiduoAdmin::Config::FILE_MANAGER)
    PartiduoAdmin::Directory.invite_user(admin, bad).errors["email"].should eq(["admin.errors.email"])
  end

  it "rattache le super-admin invité au parc, sans cabinet" do
    firm = AdminSpec.firm
    input = PartiduoAdmin::Directory::UserInput.new(email: "parc@aloli.example", role: PartiduoAdmin::Config::SUPER_ADMIN,
      firm_id: PartiduoAdmin.id?(firm.pk))
    PartiduoAdmin::Directory.invite_user(AdminSpec.super_admin, input).value!.firm_id.should be_nil
  end

  it "n'affecte un dossier qu'à un gestionnaire du même cabinet, et jamais soi-même ne se réinvite ni se désactive" do
    north = AdminSpec.firm("Nord")
    south = AdminSpec.firm("Sud")
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(north, server)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    colleague = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    foreign = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, south)
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, north)
    PartiduoAdmin::Directory.assign(admin, foreign, dossier).should be_false
    PartiduoAdmin::Directory.assign(admin, colleague, dossier).should be_false
    PartiduoAdmin::Directory.assign(admin, manager, dossier).should be_true
    PartiduoAdmin::Directory.assign(admin, manager, dossier).should be_true
    PartiduoAdmin::Assignment.filter(user_id: manager.pk).count.should eq(1)
    PartiduoAdmin::Directory.reinvite(admin, admin).should be_false
    PartiduoAdmin::Directory.set_active(admin, admin, false).should be_false
    PartiduoAdmin::Directory.set_active(manager, colleague, false).should be_false
  end

  it "désactiver un utilisateur coupe ses sessions ; un cabinet inactif ferme la connexion de ses membres" do
    firm = AdminSpec.firm
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    token = AdminSpec.session(manager)
    PartiduoAdmin::Auth::Sessions.find(token, SPEC_NOW).should_not be_nil
    PartiduoAdmin::Directory.set_active(admin, manager, false).should be_true
    PartiduoAdmin::Auth::Sessions.find(token, SPEC_NOW).should be_nil

    other = AdminSpec.session(admin)
    firm.active = false
    firm.save!
    PartiduoAdmin::Auth::Sessions.find(other, SPEC_NOW).should be_nil
  end

  it "ferme une session inactive depuis trente minutes et une invitation déjà servie ou remplacée" do
    user = AdminSpec.user
    token = AdminSpec.session(user)
    PartiduoAdmin::Auth::Sessions.find(token, SPEC_NOW + 29.minutes).should_not be_nil
    PartiduoAdmin::Auth::Sessions.find(token, SPEC_NOW + 29.minutes + 31.minutes).should be_nil

    first = PartiduoAdmin::Auth::Invitations.issue(user, now: SPEC_NOW)
    second = PartiduoAdmin::Auth::Invitations.issue(user, now: SPEC_NOW)
    PartiduoAdmin::Auth::Invitations.consume(first, SPEC_NOW).should be_nil
    PartiduoAdmin::Auth::Invitations.consume(second, SPEC_NOW + 8.days).should be_nil
    PartiduoAdmin::Auth::Invitations.consume(second, SPEC_NOW).try(&.pk).should eq(user.pk)
    PartiduoAdmin::Auth::Invitations.consume(second, SPEC_NOW).should be_nil
  end

  it "contrôle cabinets, serveurs, versions et donneurs d'ordre" do
    root = AdminSpec.super_admin
    firm_admin = AdminSpec.user
    PartiduoAdmin::Directory.create_firm(firm_admin, "Cabinet Est").errors["base"].should eq(["admin.errors.forbidden"])
    PartiduoAdmin::Directory.create_firm(root, "Cabinet Est", siren: "732829321").errors["siren"].should eq(["admin.errors.siren"])
    PartiduoAdmin::Directory.create_firm(root, "  ").errors["name"].should eq(["admin.errors.required"])
    PartiduoAdmin::Directory.create_firm(root, "Cabinet Est").ok?.should be_true
    PartiduoAdmin::Directory.create_firm(root, "Cabinet Est").errors["name"].should eq(["admin.errors.firm.taken"])

    PartiduoAdmin::Directory.create_server(root, "Hote_1", "h.example.net", "partiduo.app").errors["name"].should eq(["admin.errors.invalid"])
    PartiduoAdmin::Directory.create_server(root, "hote1", "h.example.net", "partiduo").errors["domain"].should eq(["admin.errors.invalid"])

    PartiduoAdmin::Directory.create_release(root, "v1", "", false).errors["version"].should eq(["admin.errors.invalid"])
    PartiduoAdmin::Directory.create_release(root, "0.1.0", "", true).ok?.should be_true
    PartiduoAdmin::Directory.create_release(root, "0.2.0-rc.1", "", true).ok?.should be_true
    PartiduoAdmin::Release.filter(is_default: true).map(&.version).should eq(["0.2.0-rc.1"])

    firm = AdminSpec.firm
    input = PartiduoAdmin::Directory::PayerInput.new(kind: "gratuit", firm_id: PartiduoAdmin.id?(firm.pk), name: "",
      siren: "123", street: "", city: "", country: "fr", contact_email: "x")
    errors = PartiduoAdmin::Directory.save_payer(root, input).errors
    %w[kind name street city siren country contact_email].each { |field| errors.has_key?(field).should be_true }
  end

  it "neutralise dans l'export CSV toute cellule qu'un tableur lirait comme une formule" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    ["=1+1", "+33", "-2", "@SUM", "\tcmd", "\rcmd"].each_with_index do |name, index|
      AdminSpec.dossier(firm, server, slug: "csv#{index}", payer: AdminSpec.payer(firm, "other", name))
    end
    rows = CSV.parse(PartiduoAdmin::Directory.csv(AdminSpec.super_admin))
    rows.skip(1).map(&.[2]).each(&.should(start_with("'")))
  end
end

describe "Double validation : cas limites" do
  it "expire une demande non validée à temps, et la planification clôt les demandes échues" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    approval = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti", SPEC_NOW - 8.days).value!
    PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval, SPEC_NOW).errors["base"].should eq(["admin.errors.approval.expired"])
    approval.reload.state.should eq("expired")
    PartiduoAdmin::Task.filter(kind: "instance.admin_invite").exists?.should be_false

    # Une nouvelle demande est alors possible ; échue, la planification la clôt.
    fresh = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti", SPEC_NOW - 8.days).value!
    PartiduoAdmin::Scheduler.run(SPEC_NOW)
    fresh.reload.state.should eq("expired")
  end

  it "refuse un motif trop court, une adresse invalide, un dossier non actif" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Approvals.request_admin_invite(admin, dossier, "a@b.fr", "abc").errors["reason"].should eq(["admin.errors.required"])
    PartiduoAdmin::Approvals.request_admin_invite(admin, dossier, "a@b", "motif valable").errors["email"].should eq(["admin.errors.email"])
    suspended = AdminSpec.dossier(firm, server, state: "suspended")
    PartiduoAdmin::Approvals.request_admin_invite(admin, suspended, "a@b.fr", "motif valable").errors["base"]
      .should eq(["admin.errors.dossier.not_active"])
    PartiduoAdmin::Approvals.request_delete(admin, dossier, "motif valable").errors["base"].should eq(["admin.errors.dossier.state"])
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    PartiduoAdmin::Approvals.request_delete(manager, dossier, "motif valable").errors["base"].should eq(["admin.errors.forbidden"])
  end

  it "recontrôle l'état du dossier à la validation d'un recours d'accès" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    approval = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti").value!
    dossier.state = "suspended"
    dossier.save!
    outcome = PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval)
    outcome.errors["base"].should eq(["admin.errors.dossier.not_active"])
    approval.reload.state.should eq("pending")
    PartiduoAdmin::Task.filter(kind: "instance.admin_invite").exists?.should be_false
  end

  it "recontrôle la durée légale à la validation d'une suppression" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, state: "archived")
    dossier.retention_until = SPEC_NOW - 1.day
    dossier.save!
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    approval = PartiduoAdmin::Approvals.request_delete(requester, dossier, "fin de conservation").value!
    dossier.state = "active"
    dossier.save!
    PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval).errors["base"]
      .should eq(["admin.errors.dossier.retention_running"])
  end

  it "laisse le demandeur retirer sa demande, et refuse de valider une demande close" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    stranger = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, AdminSpec.firm)
    approval = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti").value!
    PartiduoAdmin::Approvals.reject(stranger, approval).should be_false
    PartiduoAdmin::Approvals.reject(requester, approval).should be_true
    PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval.reload).errors["base"].should eq(["admin.errors.approval.state"])
    PartiduoAdmin::Approvals.visible(stranger).count.should eq(0)
  end
end

describe "Cycle de vie : cas limites" do
  it "refuse les gestes hors de l'état attendu ou d'une autre portée" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    archived = AdminSpec.dossier(firm, server, state: "archived")
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Fleet.backup_now(admin, archived).errors["base"].should eq(["admin.errors.dossier.state"])
    PartiduoAdmin::Fleet.lifecycle(admin, archived, "suspend").errors["base"].should eq(["admin.errors.dossier.state"])
    PartiduoAdmin::Fleet.lifecycle(admin, archived, "effacer").errors["base"].should eq(["admin.errors.invalid"])
    PartiduoAdmin::Fleet.change_modules(admin, archived, ["accounting"], [] of String).errors["base"]
      .should eq(["admin.errors.dossier.not_active"])

    active = AdminSpec.dossier(firm, server)
    PartiduoAdmin::Fleet.change_modules(admin, active, ["compta"], [] of String).errors["modules"].should eq(["admin.errors.dossier.modules"])
    PartiduoAdmin::Fleet.change_modules(admin, active, [] of String, [] of String).errors["modules"].should eq(["admin.errors.dossier.modules"])
    PartiduoAdmin::Fleet.change_modules(admin, active, ["accounting"], ["Mauvais;rm"]).errors["extensions"]
      .should eq(["admin.errors.dossier.extensions"])
    PartiduoAdmin::Fleet.restore(admin, active, SPEC_NOW, "ailleurs").errors["target"].should eq(["admin.errors.invalid"])

    foreign = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, AdminSpec.firm)
    PartiduoAdmin::Fleet.lifecycle(foreign, active, "suspend").errors["base"].should eq(["admin.errors.forbidden"])
    PartiduoAdmin::Fleet.backup_now(foreign, active).errors["base"].should eq(["admin.errors.forbidden"])
  end

  it "ne monte pas un dossier à sa propre version, et refuse la montée au gestionnaire" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, version: "0.2.0")
    release = PartiduoAdmin::Release.create!(version: "0.2.0")
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Fleet.upgrade(admin, dossier, release).errors["release_id"].should eq(["admin.errors.release.same"])
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    other = PartiduoAdmin::Release.create!(version: "0.3.0")
    PartiduoAdmin::Fleet.upgrade(manager, dossier, other).errors["base"].should eq(["admin.errors.forbidden"])
  end

  it "refuse la restauration test d'une sauvegarde échouée ou élaguée" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    backup = AdminSpec.backup(dossier)
    %w[failed pruned pending].each do |state|
      backup.state = state
      backup.save!
      PartiduoAdmin::Fleet.test_restore(nil, backup).errors["base"].should eq(["admin.errors.backup.unusable"])
    end
  end

  it "passe un dossier en erreur si sa création échoue, et le rejeu remet la tâche en file" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    root = AdminSpec.super_admin
    dossier = PartiduoAdmin::Fleet.create_dossier(root, dossier_input(firm, server, AdminSpec.payer(firm))).value!
    task = PartiduoAdmin::Task.get!(dossier_id: dossier.pk)
    finish_task(task, false)
    dossier.reload.state.should eq("error")
    PartiduoAdmin::Tasks.retry(root, task).should be_true
    task.reload.state.should eq("pending")
    dossier.reload.state.should eq("error")
    PartiduoAdmin::Tasks.retry(root, task).should be_false
    PartiduoAdmin::Tasks.cancel(root, task).should be_true
    PartiduoAdmin::Tasks.cancel(root, task.reload).should be_false
  end

  it "ne compte pas les certificats de l'autorité de test ni ceux de plus d'une semaine dans le quota" do
    40.times { |i| PartiduoAdmin::CertificateIssue.create!(host: "s#{i}.partiduo.app", domain: "partiduo.app", staging: true, issued_at: SPEC_NOW) }
    20.times { |i| PartiduoAdmin::CertificateIssue.create!(host: "o#{i}.partiduo.app", domain: "partiduo.app", issued_at: SPEC_NOW - 8.days) }
    PartiduoAdmin::LetsEncrypt.issued_last_week("partiduo.app", SPEC_NOW).should eq(0)
    40.times { |i| PartiduoAdmin::CertificateIssue.create!(host: "p#{i}.partiduo.app", domain: "partiduo.app", issued_at: SPEC_NOW - 1.day) }
    PartiduoAdmin::LetsEncrypt.quota_reached?("partiduo.app", SPEC_NOW).should be_false
    AdminSpec.server(domain: "partiduo.app")
    PartiduoAdmin::Supervision.evaluate(SPEC_NOW)
    alert = PartiduoAdmin::Alert.get!(kind: "le_quota", resolved_at__isnull: true)
    alert.severity.should eq("warning")
    # Domaine de développement : jamais de quota.
    60.times { |i| PartiduoAdmin::CertificateIssue.create!(host: "l#{i}.partiduo.localhost", domain: "partiduo.localhost", issued_at: SPEC_NOW) }
    PartiduoAdmin::LetsEncrypt.quota_reached?("partiduo.localhost", SPEC_NOW).should be_false
  end
end

describe "Vagues et planification : cas limites" do
  it "libère les lots dans l'ordre et termine la vague quand tout a réussi" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    3.times { |i| AdminSpec.dossier(firm, server, slug: "lot#{i}") }
    AdminSpec.dossier(firm, server, slug: "deja", version: "0.4.0")
    AdminSpec.dossier(firm, server, slug: "suspendu", state: "suspended")
    release = PartiduoAdmin::Release.create!(version: "0.4.0")
    root = AdminSpec.super_admin
    PartiduoAdmin::Waves.start(root, release, 0).errors["batch_size"].should eq(["admin.errors.invalid"])
    wave = PartiduoAdmin::Waves.start(root, release, 2).value!
    tasks = PartiduoAdmin::Task.filter(wave_id: wave.pk).order("id").to_a
    tasks.map(&.dossier_slug).should eq(%w[lot0 lot1 lot2])
    tasks.map(&.state).should eq(%w[pending pending waiting])
    # Une tâche retenue n'est jamais remise à l'exécutant.
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW).try(&.pk).should eq(tasks[0].pk)
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW).try(&.pk).should eq(tasks[1].pk)
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW).should be_nil

    finish_task(tasks[0], true, {"version" => "0.4.0"})
    tasks[2].reload.state.should eq("waiting")
    finish_task(tasks[1].reload, true, {"version" => "0.4.0"})
    tasks[2].reload.state.should eq("pending")
    finish_task(tasks[2].reload, true, {"version" => "0.4.0"})
    wave.reload.state.should eq("done")
    PartiduoAdmin::Waves.start(root, release, 2).errors["base"].should eq(["admin.errors.wave.nothing"])
  end

  it "n'élague ni une archive figée ni la dernière sauvegarde réussie, et respecte le rythme hebdomadaire" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    dossier.backup_schedule = "weekly"
    dossier.save!
    frozen = AdminSpec.backup(dossier, SPEC_NOW - 400.days, kind: "archive")
    frozen.frozen = true
    frozen.save!
    latest = AdminSpec.backup(dossier, SPEC_NOW - 3.days, kind: "scheduled")
    latest.keep_until = SPEC_NOW - 1.day
    latest.save!
    summary = PartiduoAdmin::Scheduler.run(SPEC_NOW)
    summary.backups.should eq(0)
    summary.prunes.should eq(0)

    quiet = AdminSpec.dossier(firm, server, slug: "sans-sauvegarde")
    quiet.backup_schedule = "none"
    quiet.save!
    PartiduoAdmin::Scheduler.run(SPEC_NOW)
    PartiduoAdmin::Task.filter(dossier_id: quiet.pk, kind: "backup.run").exists?.should be_false
  end

  it "résout une alerte quand la condition disparaît, sans la dupliquer tant qu'elle dure" do
    server, _ = AdminSpec.server
    server.last_seen_at = SPEC_NOW - 2.hours
    server.save!
    PartiduoAdmin::Supervision.evaluate(SPEC_NOW)
    PartiduoAdmin::Supervision.evaluate(SPEC_NOW)
    PartiduoAdmin::Alert.filter(kind: "agent_silent").count.should eq(1)
    server.last_seen_at = SPEC_NOW
    server.save!
    PartiduoAdmin::Supervision.evaluate(SPEC_NOW)
    PartiduoAdmin::Alert.filter(kind: "agent_silent", resolved_at__isnull: true).exists?.should be_false
  end

  it "montre à chacun les alertes de sa portée" do
    north = AdminSpec.firm
    south = AdminSpec.firm
    server, _ = AdminSpec.server
    a = AdminSpec.dossier(north, server)
    b = AdminSpec.dossier(south, server)
    PartiduoAdmin::Alerts.open("service", "danger", dossier: a, now: SPEC_NOW)
    PartiduoAdmin::Alerts.open("service", "danger", dossier: b, now: SPEC_NOW)
    PartiduoAdmin::Alerts.open("disk_low", "danger", server: server, now: SPEC_NOW)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    PartiduoAdmin::Alerts.visible(admin).map(&.dossier_id).should eq([a.pk])
    PartiduoAdmin::Alerts.visible(AdminSpec.super_admin).count.should eq(3)
  end
end

describe "API de l'exécutant : cas limites" do
  it "refuse le compte rendu d'une tâche qui n'est pas en cours, et d'un serveur désactivé" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    task = PartiduoAdmin::Fleet.backup_now(nil, AdminSpec.dossier(firm, server)).value!
    agent_call("/api/agent/v1/tasks/#{task.pk}/log", token, %({"lines":["x"]})).status.should eq(409)
    agent_call("/api/agent/v1/tasks/#{task.pk}/finish", token, %({"ok":true})).status.should eq(409)
    agent_call("/api/agent/v1/tasks/999999/finish", token, %({"ok":true})).status.should eq(404)
    task.reload.state.should eq("pending")

    server.active = false
    server.save!
    agent_call("/api/agent/v1/claim", token).status.should eq(401)
  end

  it "traite un corps illisible comme un échec, jamais comme une réussite" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    task = PartiduoAdmin::Fleet.backup_now(nil, AdminSpec.dossier(firm, server)).value!
    agent_call("/api/agent/v1/claim", token).status.should eq(200)
    agent_call("/api/agent/v1/tasks/#{task.pk}/finish", token, "{pas du json").status.should eq(200)
    task.reload.state.should eq("failed")
    PartiduoAdmin::Backup.get!(dossier_id: task.dossier_id).state.should eq("failed")
  end

  it "borne le journal conservé d'une tâche" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    task = PartiduoAdmin::Fleet.backup_now(nil, AdminSpec.dossier(firm, server)).value!
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW)
    line = "x" * 1000
    300.times { PartiduoAdmin::Tasks.report(task, [line], SPEC_NOW) }
    task.reload.log.to_s.size.should eq(PartiduoAdmin::Tasks::LOG_LIMIT)
    PartiduoAdmin::Tasks.report(task, ["a\nb\rc"], SPEC_NOW)
  end
end
