# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

private def input(firm, server, payer, slug = "demo-fr", payer_id = :default, package = "app")
  PartiduoAdmin::Fleet::DossierInput.new(slug: slug, label: "Démo FR SARL", regime: "fr", siren: "732829320",
    modules: ["accounting", "invoicing"], extensions: ["skel"], admin_email: "patron@demo.fr",
    server_id: PartiduoAdmin.id?(server.pk), firm_id: PartiduoAdmin.id?(firm.pk), payer_id: payer_id == :default ? PartiduoAdmin.id?(payer.pk) : nil,
    package: package)
end

private def finish(task, ok = true, result = {} of String => String)
  task.state = "running"
  task.save!
  PartiduoAdmin::Tasks.finish(task, ok, JSON.parse(result.to_json), ok ? "" : "échec", ["fait"], SPEC_NOW)
  task.reload
end

describe PartiduoAdmin::Fleet do
  it "crée un dossier avec donneur d'ordre obligatoire et met sa création en file" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    payer = AdminSpec.payer(firm)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)

    refused = PartiduoAdmin::Fleet.create_dossier(admin, input(firm, server, payer, payer_id: nil))
    refused.errors["payer_id"].should eq(["admin.errors.dossier.payer_required"])

    outcome = PartiduoAdmin::Fleet.create_dossier(admin, input(firm, server, payer))
    outcome.ok?.should be_true
    dossier = outcome.value!
    dossier.state.should eq("creating")
    task = PartiduoAdmin::Task.get!(dossier_id: dossier.pk)
    task.kind.should eq("instance.create")
    task.params_json["name"].should eq("Démo FR SARL")
    task.params_json["extensions"].as_a.map(&.as_s).should eq(["skel"])
    task.params_json["host"].should eq("demo-fr.partiduo.localhost")
    dossier.package.should eq("app")
    task.params_json["package"].should eq("app")
    task.params_json["version"]?.should be_nil

    PartiduoAdmin::Fleet.create_dossier(admin, input(firm, server, payer)).errors["slug"].should eq(["admin.errors.dossier.slug_taken"])
  end

  it "refuse la création quand le quota Let's Encrypt du domaine est atteint" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server(domain: "partiduo.app")
    payer = AdminSpec.payer(firm)
    50.times { |i| PartiduoAdmin::CertificateIssue.create!(host: "d#{i}.partiduo.app", domain: "partiduo.app", issued_at: SPEC_NOW - 1.day) }
    outcome = PartiduoAdmin::Fleet.create_dossier(AdminSpec.super_admin, input(firm, server, payer, "quota"))
    outcome.errors["base"].should eq(["admin.errors.dossier.quota"])
    PartiduoAdmin::LetsEncrypt.usage(SPEC_NOW).first.level.should eq("danger")
  end

  it "applique le résultat de la création : actif, version, courriel d'invitation, lien non conservé" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = PartiduoAdmin::Fleet.create_dossier(AdminSpec.super_admin, input(firm, server, AdminSpec.payer(firm), "cree")).value!
    task = PartiduoAdmin::Task.get!(dossier_id: dossier.pk)
    finish(task, true, {"database" => "partiduo_cree", "version" => "0.1.0",
                        "invitation_url" => "https://cree.partiduo.localhost/invitation/SECRET"})
    dossier.reload
    dossier.state.should eq("active")
    dossier.database.should eq("partiduo_cree")
    task.result.to_s.should_not contain("SECRET")
    Marten::Spec.delivered_emails.flat_map(&.to).map(&.address).should contain("patron@demo.fr")
    Marten::Spec.delivered_emails.last.text_body.to_s.should contain("/invitation/SECRET")
  end

  it "traduit un changement de modules en activations et désactivations" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Fleet.change_modules(admin, dossier, ["accounting", "invoicing"], [] of String).errors["base"]
      .should eq(["admin.errors.dossier.no_change"])
    task = PartiduoAdmin::Fleet.change_modules(admin, dossier, ["accounting", "analytic"], ["skel"]).value!
    task.params_json["enable"].as_a.map(&.as_s).should eq(["analytic", "skel"])
    task.params_json["disable"].as_a.map(&.as_s).should eq(["invoicing"])
    finish(task)
    dossier.reload.modules.should eq("accounting,analytic")
    dossier.extensions.should eq("skel")
  end

  it "suit le cycle de vie : suspendre, réactiver, archiver (dix ans), restaurer" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Fleet.lifecycle(admin, dossier, "resume").errors["base"].should eq(["admin.errors.dossier.state"])
    finish(PartiduoAdmin::Fleet.lifecycle(admin, dossier, "suspend").value!)
    dossier.reload.state.should eq("suspended")
    finish(PartiduoAdmin::Fleet.lifecycle(admin, dossier, "resume").value!)
    dossier.reload.state.should eq("active")

    task = PartiduoAdmin::Fleet.lifecycle(admin, dossier, "archive", "cessation d'activité").value!
    finish(task, true, {"backup" => {"path" => "/var/backups/partiduo/x/archive.dump", "sha256" => "a" * 64, "verified" => true}})
    dossier.reload.state.should eq("archived")
    dossier.retention_until.should eq(SPEC_NOW.shift(years: 10))
    archive = PartiduoAdmin::Backup.get!(dossier_id: dossier.pk, kind: "archive")
    archive.frozen.should be_true
    archive.state.should eq("verified")

    finish(PartiduoAdmin::Fleet.lifecycle(admin, dossier, "restore_archive").value!)
    dossier.reload.state.should eq("active")
    dossier.retention_until.should be_nil
  end

  it "refuse au gestionnaire les gestes réservés aux admins" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    PartiduoAdmin::Fleet.lifecycle(manager, dossier, "archive").errors["base"].should eq(["admin.errors.forbidden"])
    PartiduoAdmin::Fleet.backup_now(manager, dossier).ok?.should be_true
  end

  it "restaure à une date la dernière sauvegarde prise avant, dans une instance neuve du même paquet" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, package: "devel")
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    old = AdminSpec.backup(dossier, SPEC_NOW - 10.days)
    AdminSpec.backup(dossier, SPEC_NOW - 1.day)
    PartiduoAdmin::Fleet.restore(admin, dossier, SPEC_NOW - 20.days, "new", "copie").errors["date"]
      .should eq(["admin.errors.backup.none_before"])
    task = PartiduoAdmin::Fleet.restore(admin, dossier, SPEC_NOW - 5.days, "new", "copie").value!
    task.params_json["backup_id"].as_i64.should eq(old.pk)
    PartiduoAdmin::Dossier.get!(slug: "copie").state.should eq("creating")
    PartiduoAdmin::Dossier.get!(slug: "copie").package.should eq("devel")
    task.params_json["package"].should eq("devel")
    finish(task, true, {"database" => "partiduo_copie", "version" => "0.1.0"})
    PartiduoAdmin::Dossier.get!(slug: "copie").state.should eq("active")
  end
end

describe PartiduoAdmin::Approvals do
  it "exige la durée légale écoulée et une seconde personne pour supprimer" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, state: "archived")
    dossier.retention_until = SPEC_NOW + 1.year
    dossier.save!
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    second = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)

    PartiduoAdmin::Approvals.request_delete(requester, dossier, "fin de conservation").errors["base"]
      .should eq(["admin.errors.dossier.retention_running"])

    dossier.retention_until = SPEC_NOW - 1.day
    dossier.save!
    AdminSpec.backup(dossier)
    approval = PartiduoAdmin::Approvals.request_delete(requester, dossier, "fin de conservation").value!
    PartiduoAdmin::Approvals.approve(requester, approval).errors["base"].should eq(["admin.errors.approval.same_person"])
    task = PartiduoAdmin::Approvals.approve(second, approval).value!
    task.kind.should eq("instance.delete")
    task.params_json["approvers"].as_a.map(&.as_s).should eq([requester.email, second.email])
    task.params_json["approval_ref"].should eq(approval.reference)
    task.params_json["backups"].as_a.size.should eq(2)
    finish(task)
    dossier.reload.state.should eq("deleted")
    PartiduoAdmin::Backup.filter(dossier_id: dossier.pk, state: "pruned").count.should eq(1)
  end

  it "réémet l'invitation d'administrateur après double validation, trace comprise" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: dossier)
    approval = PartiduoAdmin::Approvals.request_admin_invite(manager, dossier, "nouveau@demo.fr", "gérant parti sans transmettre").value!
    PartiduoAdmin::Approvals.request_admin_invite(manager, dossier, "nouveau@demo.fr", "doublon !").errors["base"]
      .should eq(["admin.errors.approval.already_pending"])
    other_manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    PartiduoAdmin::Assignment.create!(user: other_manager, dossier: dossier)
    PartiduoAdmin::Approvals.approve(other_manager, approval).errors["base"].should eq(["admin.errors.forbidden"])
    task = PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval).value!
    task.kind.should eq("instance.admin_invite")
    task.params_json["email"].should eq("nouveau@demo.fr")
    finish(task, true, {"email" => "nouveau@demo.fr", "url" => "https://x/invitation/TOKEN", "usable_admins" => "0"})
    task.result.to_s.should_not contain("TOKEN")
    Marten::Spec.delivered_emails.last.to.map(&.address).should eq(["nouveau@demo.fr"])
    PartiduoAdmin::AuditEntry.filter(action: "approval.approve").count.should eq(1)
  end
end

describe "PartiduoAdmin : paquet d'un dossier" do
  it "crée un dossier servi par partiduo-app-devel et transmet le paquet à l'exécutant" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = PartiduoAdmin::Fleet.create_dossier(AdminSpec.super_admin, input(firm, server, AdminSpec.payer(firm), "essai-devel",
      package: "devel")).value!
    dossier.package.should eq("devel")
    dossier.package_name.should eq("partiduo-app-devel")
    task = PartiduoAdmin::Task.get!(dossier_id: dossier.pk, kind: "instance.create")
    task.params_json["package"].should eq("devel")
    # Toute tâche du dossier porte son paquet.
    PartiduoAdmin::Tasks.dossier_params(dossier)["package"].should eq("devel")
  end

  it "refuse un paquet inconnu, jamais une valeur libre" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    payer = AdminSpec.payer(firm)
    %w[beta ../../tmp/piege partiduo-app].each_with_index do |package, index|
      outcome = PartiduoAdmin::Fleet.create_dossier(AdminSpec.super_admin, input(firm, server, payer, "paquet#{index}", package: package))
      outcome.errors["package"].should eq(["admin.errors.dossier.package"])
    end
    PartiduoAdmin::Dossier.filter(slug__startswith: "paquet").exists?.should be_false
    PartiduoAdmin::Protocol.valid_package?("app").should be_true
    PartiduoAdmin::Protocol.valid_package?("devel").should be_true
    PartiduoAdmin::Protocol.valid_package?("").should be_false
  end
end

describe PartiduoAdmin::Scheduler do
  it "planifie sauvegardes, élagage, restauration test et supervision, et lève les alertes" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    old = AdminSpec.backup(dossier, SPEC_NOW - 40.days)
    AdminSpec.backup(dossier, SPEC_NOW - 2.days)
    summary = PartiduoAdmin::Scheduler.run(SPEC_NOW)
    summary.backups.should eq(1)
    summary.prunes.should eq(1)
    summary.test_restores.should eq(1)
    summary.checks.should eq(1)
    prune = PartiduoAdmin::Task.get!(kind: "backup.prune")
    prune.params_json["backup_ids"].as_a.map(&.as_i64).should eq([old.pk])
    PartiduoAdmin::Alert.filter(kind: "backup_age", resolved_at__isnull: true).exists?.should be_true
    PartiduoAdmin::Alert.filter(kind: "agent_silent", resolved_at__isnull: true).exists?.should be_true
    # Deuxième passage : rien en double.
    PartiduoAdmin::Scheduler.run(SPEC_NOW).backups.should eq(0)
    PartiduoAdmin::Task.filter(kind: "backup.run").count.should eq(1)
  end

  it "met à jour la supervision et ouvre ou résout les alertes" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server, slug: "surveille")
    result = JSON.parse({
      "disk"     => {"total_bytes" => 100, "free_bytes" => 5},
      "dossiers" => [{"slug" => "surveille", "service" => "stopped", "database" => "ok", "version" => "0.1.0",
                      "cert_expires_at" => (SPEC_NOW + 5.days).to_rfc3339}],
    }.to_json)
    PartiduoAdmin::Supervision.apply(server, true, result, SPEC_NOW)
    kinds = PartiduoAdmin::Alert.filter(resolved_at__isnull: true).map(&.kind.to_s).sort!
    kinds.should eq(%w[certificate disk_low service])
    dossier.reload.service_state.should eq("stopped")
    ok = JSON.parse({"disk"     => {"total_bytes" => 100, "free_bytes" => 50},
                     "dossiers" => [{"slug" => "surveille", "service" => "running", "database" => "ok"}]}.to_json)
    PartiduoAdmin::Supervision.apply(server, true, ok, SPEC_NOW)
    PartiduoAdmin::Alert.filter(resolved_at__isnull: true).count.should eq(0)
  end
end
