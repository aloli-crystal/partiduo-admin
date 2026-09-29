# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Validation à deux au choix (décision du 29 septembre 2026, D-VAL2-001 à
# D-VAL2-007) : réglage par structure, protection de repli à une personne,
# bascules, équipe réduite, droits, écrans.

private alias Cfg = PartiduoAdmin::Config
private alias Mode = PartiduoAdmin::ApprovalMode

# Dossier archivé dont la durée légale est écoulée : supprimable.
private def expired_archive(firm : PartiduoAdmin::Firm, server : PartiduoAdmin::Server, slug : String) : PartiduoAdmin::Dossier
  dossier = AdminSpec.dossier(firm, server, state: "archived", slug: slug)
  dossier.archived_at = SPEC_NOW - (11 * 365).days
  dossier.retention_until = SPEC_NOW - 1.day
  dossier.save!
  AdminSpec.backup(dossier, SPEC_NOW - (11 * 365).days, "archive")
  dossier
end

# Session ouverte au niveau exigé ; `strong_ago` recule l'heure de la
# dernière authentification forte.
private def session_for(user : PartiduoAdmin::User, strong_ago : Time::Span? = nil) : {String, PartiduoAdmin::Session}
  opened = PartiduoAdmin::Auth::Sessions.open(user, PartiduoAdmin::Auth.required_level(user), "spec", now: SPEC_NOW)
  if ago = strong_ago
    opened.session.strong_auth_at = SPEC_NOW - ago
    opened.session.save!
  end
  {opened.token, opened.session}
end

private def two_admins(name : String) : {PartiduoAdmin::Firm, PartiduoAdmin::User, PartiduoAdmin::User}
  firm = AdminSpec.firm(name)
  {firm, AdminSpec.user(Cfg::FIRM_ADMIN, firm), AdminSpec.user(Cfg::FIRM_ADMIN, firm)}
end

describe "Validation à deux : réglage par structure (D-VAL2-001 à D-VAL2-003)" do
  it "est désactivée par défaut pour un gestionnaire indépendant et un cabinet d'une personne" do
    root = AdminSpec.super_admin
    independent = PartiduoAdmin::Directory.create_firm(root, "Martine Durand", kind: "independent").value!
    solo = PartiduoAdmin::Directory.create_firm(root, "Cabinet Solo").value!
    AdminSpec.user(Cfg::FIRM_ADMIN, independent)
    AdminSpec.user(Cfg::FIRM_ADMIN, solo)
    Mode.mode(independent).should eq(Mode::SINGLE)
    Mode.mode(solo).should eq(Mode::SINGLE)
    Mode.suggested?(independent).should be_false
    Mode.suggested?(solo).should be_false
  end

  it "est proposée, sans être imposée, à un cabinet de plusieurs personnes habilitées" do
    firm, first, _second = two_admins("Cabinet Duo")
    Mode.mode(firm).should eq(Mode::SINGLE)
    Mode.suggested?(firm).should be_true
    Mode.set(first, firm, true).ok?.should be_true
    Mode.mode(firm).should eq(Mode::DUAL)
    Mode.suggested?(firm).should be_false
    entry = PartiduoAdmin::AuditEntry.filter(action: "dual_approval.change").first!
    JSON.parse(entry.detail.to_s)["after"].should eq("dual")
    JSON.parse(entry.detail.to_s)["team"].should eq("2")
    # Retour à une personne : au choix, tracé aussi.
    Mode.set(first, firm, false).ok?.should be_true
    PartiduoAdmin::AuditEntry.filter(action: "dual_approval.change").count.should eq(2)
  end

  it "refuse de l'activer sans deux personnes habilitées (un gestionnaire de dossiers ne compte pas)" do
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    AdminSpec.user(Cfg::FILE_MANAGER, firm)
    outcome = Mode.set(admin, firm, true)
    outcome.errors["mode"].should eq(["admin.errors.dual_approval.team"])
    firm.reload.dual_approval.should be_false
    PartiduoAdmin::AuditEntry.filter(action: "dual_approval.change").count.should eq(0)
  end

  it "se désactive d'elle-même si l'équipe retombe à une personne, avec une trace au journal d'audit" do
    firm, first, second = two_admins("Cabinet Réduit")
    Mode.set(first, firm, true).ok?.should be_true
    PartiduoAdmin::Directory.set_active(first, second, false).should be_true
    firm.reload.dual_approval.should be_false
    entry = PartiduoAdmin::AuditEntry.filter(action: "dual_approval.auto_off").first!
    entry.actor_label.should eq("system")
    entry.firm_id.should eq(firm.pk)
    JSON.parse(entry.detail.to_s)["team"].should eq("1")
    # Une seule trace, même si l'on réconcilie de nouveau.
    Mode.reconcile_all.should eq(0)
    PartiduoAdmin::AuditEntry.filter(action: "dual_approval.auto_off").count.should eq(1)
  end

  it "se désactive aussi à la planification quand l'équipe a changé hors de l'interface" do
    firm, first, second = two_admins("Cabinet Planifié")
    Mode.set(first, firm, true).ok?.should be_true
    second.active = false
    second.save!
    PartiduoAdmin::Scheduler.run(SPEC_NOW)
    firm.reload.dual_approval.should be_false
    PartiduoAdmin::AuditEntry.filter(action: "dual_approval.auto_off").count.should eq(1)
  end

  it "laisse chaque admin régler sa structure, le super-admin seulement le parc sans cabinet" do
    firm, first, _ = two_admins("Cabinet Droits")
    other_admin = AdminSpec.user(Cfg::FIRM_ADMIN, AdminSpec.firm)
    manager = AdminSpec.user(Cfg::FILE_MANAGER, firm)
    root = AdminSpec.super_admin
    Mode.set(other_admin, firm, true).errors["base"].should eq(["admin.errors.forbidden"])
    Mode.set(manager, firm, true).errors["base"].should eq(["admin.errors.forbidden"])
    Mode.set(root, firm, true).errors["base"].should eq(["admin.errors.forbidden"])
    Mode.can_view?(root, firm).should be_true
    Mode.can_view?(other_admin, firm).should be_false
    Mode.set(first, firm, true).ok?.should be_true

    fleet = PartiduoAdmin::Directory.create_firm(root, "Parc Aloli", kind: "fleet").value!
    PartiduoAdmin::Directory.create_firm(root, "Second parc", kind: "fleet").errors["kind"].should eq(["admin.errors.firm.fleet_taken"])
    Mode.set(first, fleet, true).errors["base"].should eq(["admin.errors.forbidden"])
    # Parc sans cabinet : les super-admins sont ses personnes habilitées.
    Mode.set(root, fleet, true).errors["mode"].should eq(["admin.errors.dual_approval.team"])
    second_root = AdminSpec.super_admin
    Mode.team(fleet).map(&.email.to_s).sort!.should eq([root.email.to_s, second_root.email.to_s].sort!)
    Mode.set(root, fleet, true).ok?.should be_true
    PartiduoAdmin::Directory.set_active(root, second_root, false).should be_true
    fleet.reload.dual_approval.should be_false
  end

  it "réserve le gestionnaire indépendant à une seule personne, admin de sa structure" do
    root = AdminSpec.super_admin
    independent = PartiduoAdmin::Directory.create_firm(root, "Paul Martin", kind: "independent").value!
    input = PartiduoAdmin::Directory::UserInput.new(email: "paul@exemple.fr", role: Cfg::FILE_MANAGER, firm_id: independent.pk!.as(Int64))
    PartiduoAdmin::Directory.invite_user(root, input).errors["role"].should eq(["admin.errors.firm.independent_role"])
    first = PartiduoAdmin::Directory::UserInput.new(email: "paul@exemple.fr", role: Cfg::FIRM_ADMIN, firm_id: independent.pk!.as(Int64))
    PartiduoAdmin::Directory.invite_user(root, first).ok?.should be_true
    PartiduoAdmin::User.get!(email: "paul@exemple.fr").role_key.should eq("admin.roles.independent_manager")
    second = PartiduoAdmin::Directory::UserInput.new(email: "associe@exemple.fr", role: Cfg::FIRM_ADMIN, firm_id: independent.pk!.as(Int64))
    PartiduoAdmin::Directory.invite_user(root, second).errors["firm_id"].should eq(["admin.errors.firm.independent_single"])
    PartiduoAdmin::Directory.create_firm(root, "Inconnu", kind: "autre").errors["kind"].should eq(["admin.errors.invalid"])
  end
end

describe "Opérations sensibles à une personne (D-VAL2-004, D-VAL2-005)" do
  it "suppression définitive : ré-authentification récente et sous-domaine retapé, puis tâche « une personne »" do
    server, _ = AdminSpec.server
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    dossier = expired_archive(firm, server, "fin-seule")
    approval = PartiduoAdmin::Approvals.request_delete(admin, dossier, "fin de conservation").value!
    approval.mode.should eq("single")
    PartiduoAdmin::Approvals.can_confirm_alone?(admin, approval).should be_true
    PartiduoAdmin::Approvals.confirm_alone(admin, approval, false, "fin-seule").errors["reauth"]
      .should eq(["admin.errors.approval.reauth"])
    PartiduoAdmin::Approvals.confirm_alone(admin, approval, true, "fin-seul").errors["confirmation"]
      .should eq(["admin.errors.approval.confirmation_slug"])
    approval.reload.state.should eq("pending")
    task = PartiduoAdmin::Approvals.confirm_alone(admin, approval, true, "fin-seule").value!
    task.kind.should eq("instance.delete")
    task.params_json["approval_mode"].should eq("single")
    task.params_json["approvers"].as_a.map(&.as_s).should eq([admin.email])
    task.params_json["approval_ref"].should eq(approval.reference)
    approval.reload.state.should eq("approved")
    approval.mode.should eq("single")
    approval.decided_by_id.should eq(admin.pk)
    PartiduoAdmin::AuditEntry.filter(action: "approval.confirm_alone").count.should eq(1)
    # Jamais rejouée : une nouvelle demande est nécessaire (D-AFN-010).
    PartiduoAdmin::Approvals.confirm_alone(admin, approval, true, "fin-seule").errors["base"]
      .should eq(["admin.errors.approval.state"])
    PartiduoAdmin::Tasks.retryable?(task).should be_false
  end

  it "garde les contrôles du serveur : durée légale non écoulée, état changé depuis la demande" do
    server, _ = AdminSpec.server
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    young = AdminSpec.dossier(firm, server, state: "archived", slug: "jeune")
    young.retention_until = SPEC_NOW + (5 * 365).days
    young.save!
    PartiduoAdmin::Approvals.request_delete(admin, young, "trop tôt").errors["base"]
      .should eq(["admin.errors.dossier.retention_running"])
    dossier = expired_archive(firm, server, "rouvert")
    approval = PartiduoAdmin::Approvals.request_delete(admin, dossier, "fin de conservation").value!
    dossier.state = "active"
    dossier.save!
    PartiduoAdmin::Approvals.confirm_alone(admin, approval, true, "rouvert").errors["base"]
      .should eq(["admin.errors.dossier.retention_running"])
    approval.reload.state.should eq("pending")
  end

  it "recours d'accès : case cochée ; un gestionnaire de dossiers ne confirme jamais seul" do
    server, _ = AdminSpec.server
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    manager = AdminSpec.user(Cfg::FILE_MANAGER, firm)
    dossier = AdminSpec.dossier(firm, server, slug: "recours-seul")
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    approval = PartiduoAdmin::Approvals.request_admin_invite(manager, dossier, "gerant@demo.fr", "gérant parti").value!
    PartiduoAdmin::Approvals.can_confirm_alone?(manager, approval).should be_false
    PartiduoAdmin::Approvals.confirm_alone(manager, approval, true, "yes").errors["base"]
      .should eq(["admin.errors.approval.needs_admin"])
    # L'admin (autre personne) valide : deux personnes, quel que soit le réglage.
    task = PartiduoAdmin::Approvals.approve(admin, approval).value!
    task.params_json["approval_mode"].should eq("dual")
    task.params_json["approvers"].as_a.map(&.as_s).should eq([manager.email, admin.email])

    own = PartiduoAdmin::Approvals.request_admin_invite(admin, dossier, "gerant2@demo.fr", "second départ").value!
    PartiduoAdmin::Approvals.confirm_alone(admin, own, true, "").errors["confirmation"]
      .should eq(["admin.errors.approval.confirmation"])
    invite = PartiduoAdmin::Approvals.confirm_alone(admin, own, true, "yes").value!
    invite.kind.should eq("instance.admin_invite")
    invite.params_json["approval_mode"].should eq("single")
    invite.params_json["email"].should eq("gerant2@demo.fr")
  end

  it "reconnaît une authentification forte récente au niveau exigé seulement" do
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, AdminSpec.firm)
    _, fresh = session_for(admin)
    PartiduoAdmin::Auth::Sessions.recent_strong?(fresh, SPEC_NOW).should be_true
    PartiduoAdmin::Auth::Sessions.recent_strong?(fresh, SPEC_NOW + 6.minutes).should be_false
    _, old = session_for(admin, 10.minutes)
    PartiduoAdmin::Auth::Sessions.recent_strong?(old, SPEC_NOW).should be_false
    low = PartiduoAdmin::Auth::Sessions.open(admin, PartiduoAdmin::Auth::PASSWORD, "password", now: SPEC_NOW).session
    PartiduoAdmin::Auth::Sessions.recent_strong?(low, SPEC_NOW).should be_false
    root = AdminSpec.super_admin
    two_factor = PartiduoAdmin::Auth::Sessions.open(root, PartiduoAdmin::Auth::TWO_FACTOR, "spec", now: SPEC_NOW).session
    PartiduoAdmin::Auth::Sessions.recent_strong?(two_factor, SPEC_NOW).should be_false
    # Ré-authentification par code TOTP : la session redevient forte.
    PartiduoAdmin::Auth.reauthenticate_totp(old, "000000", now: SPEC_NOW).error.should eq("admin.errors.login.code")
    PartiduoAdmin::Auth.reauthenticate_totp(old, AdminSpec.totp_code(admin, SPEC_NOW), now: SPEC_NOW).error.should be_nil
    PartiduoAdmin::Auth::Sessions.recent_strong?(old.reload, SPEC_NOW).should be_true
    PartiduoAdmin::AuditEntry.filter(action: "auth.reauth", outcome: "ok").count.should eq(1)
  end
end

describe "Opérations sensibles à deux personnes (fonctionnement inchangé)" do
  it "exige une autre personne : le demandeur ne confirme pas seul" do
    server, _ = AdminSpec.server
    firm, first, second = two_admins("Cabinet Deux")
    Mode.set(first, firm, true).ok?.should be_true
    dossier = expired_archive(firm, server, "fin-deux")
    approval = PartiduoAdmin::Approvals.request_delete(first, dossier, "fin de conservation").value!
    approval.mode.should eq("dual")
    PartiduoAdmin::Approvals.can_confirm_alone?(first, approval).should be_false
    PartiduoAdmin::Approvals.confirm_alone(first, approval, true, "fin-deux").errors["base"]
      .should eq(["admin.errors.approval.dual_required"])
    PartiduoAdmin::Approvals.approve(first, approval).errors["base"].should eq(["admin.errors.approval.same_person"])
    task = PartiduoAdmin::Approvals.approve(second, approval).value!
    task.params_json["approval_mode"].should eq("dual")
    task.params_json["approvers"].as_a.map(&.as_s).should eq([first.email, second.email])
  end

  it "recours d'accès : validé par un autre admin, le super-admin compris" do
    server, _ = AdminSpec.server
    firm, first, _ = two_admins("Cabinet Recours")
    Mode.set(first, firm, true).ok?.should be_true
    dossier = AdminSpec.dossier(firm, server, slug: "recours-deux")
    approval = PartiduoAdmin::Approvals.request_admin_invite(first, dossier, "gerant@demo.fr", "gérant parti").value!
    PartiduoAdmin::Approvals.confirm_alone(first, approval, true, "yes").ok?.should be_false
    task = PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval).value!
    task.params_json["approval_mode"].should eq("dual")
  end
end

describe "Bascules du réglage et demandes en attente (D-VAL2-006)" do
  it "une demande en attente reste en attente si l'on passe à deux personnes" do
    server, _ = AdminSpec.server
    firm, first, second = two_admins("Cabinet Bascule")
    dossier = expired_archive(firm, server, "bascule-deux")
    approval = PartiduoAdmin::Approvals.request_delete(first, dossier, "fin de conservation").value!
    approval.mode.should eq("single")
    Mode.set(second, firm, true).ok?.should be_true
    JSON.parse(PartiduoAdmin::AuditEntry.filter(action: "dual_approval.change").first!.detail.to_s)["pending"].should eq("1")
    approval.reload.state.should eq("pending")
    PartiduoAdmin::Approvals.confirm_alone(first, approval, true, "bascule-deux").errors["base"]
      .should eq(["admin.errors.approval.dual_required"])
    PartiduoAdmin::Approvals.approve(second, approval).ok?.should be_true
  end

  it "une demande en attente d'un second validateur peut être confirmée par le demandeur seul si l'on repasse à une personne" do
    server, _ = AdminSpec.server
    firm, first, second = two_admins("Cabinet Retour")
    Mode.set(first, firm, true).ok?.should be_true
    dossier = AdminSpec.dossier(firm, server, slug: "retour-seul")
    approval = PartiduoAdmin::Approvals.request_admin_invite(first, dossier, "gerant@demo.fr", "gérant parti").value!
    approval.mode.should eq("dual")
    Mode.set(second, firm, false).ok?.should be_true
    approval.reload.state.should eq("pending")
    PartiduoAdmin::Approvals.can_confirm_alone?(first, approval).should be_true
    PartiduoAdmin::Approvals.confirm_alone(first, approval, false, "yes").errors["reauth"]
      .should eq(["admin.errors.approval.reauth"])
    task = PartiduoAdmin::Approvals.confirm_alone(first, approval, true, "yes").value!
    task.params_json["approval_mode"].should eq("single")
  end

  it "équipe réduite à une personne : la demande en attente se confirme seule" do
    server, _ = AdminSpec.server
    firm, first, second = two_admins("Cabinet Départ")
    Mode.set(first, firm, true).ok?.should be_true
    dossier = expired_archive(firm, server, "depart")
    approval = PartiduoAdmin::Approvals.request_delete(first, dossier, "fin de conservation").value!
    PartiduoAdmin::Directory.set_active(first, second, false).should be_true
    PartiduoAdmin::Approvals.confirm_alone(first, approval, true, "depart").ok?.should be_true
  end
end

describe "Écrans de la validation à deux" do
  it "règle la validation à deux depuis l'écran de la structure, dans les trois langues" do
    firm, first, _ = two_admins("Cabinet Écran")
    token, _ = session_for(first)
    {"fr" => "Validation à deux", "en" => "Dual approval", "nl" => "Goedkeuring door twee"}.each do |locale, title|
      first.locale = locale
      first.save!
      page = AdminSpec::Browser.new(locale, token: token).get("/firms/#{firm.pk}/approval-mode")
      page.status.should eq(200)
      page.html.should contain(title)
      page.html.should contain(%(<html lang="#{locale}">))
      page.html.should contain(%(name="mode" value="dual"))
    end
    first.locale = "fr"
    first.save!
    browser = AdminSpec::Browser.new("fr", token: token)
    browser.get("/firms/#{firm.pk}/approval-mode").html.should contain("la validation à deux est proposée")
    browser.post("/firms/#{firm.pk}/approval-mode", {"mode" => "dual"}).status.should eq(302)
    firm.reload.dual_approval.should be_true
    browser.post("/firms/#{firm.pk}/approval-mode", {"mode" => "n'importe"}).status.should eq(422)
  end

  it "désactive le choix « deux personnes » d'une structure d'une seule personne et le refuse côté serveur" do
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    token, _ = session_for(admin)
    browser = AdminSpec::Browser.new("fr", token: token)
    html = browser.get("/firms/#{firm.pk}/approval-mode").html
    html.should match(/value="dual"[^>]*disabled/)
    html.should contain("au moins deux personnes habilitées")
    browser.post("/firms/#{firm.pk}/approval-mode", {"mode" => "dual"}).status.should eq(422)
    firm.reload.dual_approval.should be_false
  end

  it "montre le réglage d'un cabinet au super-admin sans le lui laisser changer, refuse les autres admins" do
    firm, _, _ = two_admins("Cabinet Vu")
    root_token, _ = session_for(AdminSpec.super_admin)
    root = AdminSpec::Browser.new("fr", token: root_token)
    root.get("/firms/#{firm.pk}/approval-mode").html.should contain("Réglé par l'admin de la structure")
    root.post("/firms/#{firm.pk}/approval-mode", {"mode" => "dual"}).status.should eq(403)
    stranger_token, _ = session_for(AdminSpec.user(Cfg::FIRM_ADMIN, AdminSpec.firm))
    AdminSpec::Browser.new("fr", token: stranger_token).get("/firms/#{firm.pk}/approval-mode").status.should eq(403)
    manager_token, _ = session_for(AdminSpec.user(Cfg::FILE_MANAGER, firm))
    AdminSpec::Browser.new("fr", token: manager_token).get("/firms/#{firm.pk}/approval-mode").status.should eq(403)
  end

  it "mène le demandeur seul de la demande à la tâche : ré-authentification, sous-domaine retapé" do
    server, _ = AdminSpec.server
    firm = AdminSpec.firm
    admin = AdminSpec.user(Cfg::FIRM_ADMIN, firm)
    dossier = expired_archive(firm, server, "ecran-seul")
    token, session = session_for(admin, 10.minutes)
    browser = AdminSpec::Browser.new("fr", token: token)
    browser.get("/dossiers/#{dossier.pk}").html.should contain("Continuer vers la confirmation")
    requested = browser.post("/dossiers/#{dossier.pk}/requests/delete", {"reason" => "fin de conservation"})
    requested.status.should eq(302)
    approval = PartiduoAdmin::Approval.filter(dossier_id: dossier.pk).first!
    requested.headers["Location"].should eq("/approvals/#{approval.pk}/confirm")
    page = browser.get("/approvals/#{approval.pk}/confirm").html
    page.should contain("Confirmez votre identité")
    page.should contain(%(action="/reauth/totp"))
    # Sans ré-authentification récente : refus, rien n'est lancé.
    browser.post("/approvals/#{approval.pk}/confirm", {"confirmation" => "ecran-seul"}).status.should eq(422)
    PartiduoAdmin::Task.filter(kind: "instance.delete").exists?.should be_false
    back = browser.post("/reauth/totp", {"code" => AdminSpec.totp_code(admin, SPEC_NOW), "next" => "/approvals/#{approval.pk}/confirm"})
    back.headers["Location"].should eq("/approvals/#{approval.pk}/confirm")
    session.reload.strong_auth_at.should eq(SPEC_NOW)
    browser.get("/approvals/#{approval.pk}/confirm").html.should contain("Identité confirmée")
    wrong = browser.post("/approvals/#{approval.pk}/confirm", {"confirmation" => "autre"})
    wrong.status.should eq(422)
    wrong.html.should contain(%(aria-invalid="true"))
    done = browser.post("/approvals/#{approval.pk}/confirm", {"confirmation" => "ecran-seul"})
    done.status.should eq(302)
    task = PartiduoAdmin::Task.filter(kind: "instance.delete").first!
    done.headers["Location"].should eq("/tasks/#{task.pk}")
    browser.get("/tasks/#{task.pk}").html.should contain("une personne")
  end

  it "en mode deux personnes, garde la demande en attente d'un autre et le dit au demandeur" do
    server, _ = AdminSpec.server
    firm, first, second = two_admins("Cabinet Écran Deux")
    Mode.set(first, firm, true).ok?.should be_true
    dossier = AdminSpec.dossier(firm, server, slug: "ecran-deux")
    token, _ = session_for(first)
    browser = AdminSpec::Browser.new("en", token: token)
    first.locale = "en"
    first.save!
    requested = browser.post("/dossiers/#{dossier.pk}/requests/access", {"email" => "boss@demo.fr", "reason" => "manager left"})
    requested.headers["Location"].should eq("/dossiers/#{dossier.pk}")
    approval = PartiduoAdmin::Approval.filter(dossier_id: dossier.pk).first!
    browser.get("/approvals/#{approval.pk}/confirm").html.should contain("now requires dual approval")
    browser.post("/approvals/#{approval.pk}/confirm", {"confirm" => "yes"}).status.should eq(422)
    other_token, _ = session_for(second)
    list = AdminSpec::Browser.new("fr", token: other_token).get("/approvals").html
    list.should contain("deux personnes")
    list.should contain("/approvals/#{approval.pk}/approve")
  end

  it "crée les trois natures de structure et affiche leur mode dans la liste" do
    token, _ = session_for(AdminSpec.super_admin)
    browser = AdminSpec::Browser.new("fr", token: token)
    browser.post("/firms", {"name" => "Cabinet Liste", "kind" => "cabinet"}).status.should eq(302)
    browser.post("/firms", {"name" => "Julie Petit", "kind" => "independent"}).status.should eq(302)
    browser.post("/firms", {"name" => "Parc Aloli", "kind" => "fleet"}).status.should eq(302)
    html = browser.get("/firms").html
    html.should contain("Gestionnaire indépendant")
    html.should contain("Parc sans cabinet")
    html.should contain("une personne")
    html.should_not contain(%(<option value="fleet"))
    fleet = PartiduoAdmin::Firm.filter(kind: "fleet").first!
    browser.get("/").html.should contain("/firms/#{fleet.pk}/approval-mode")
  end
end
