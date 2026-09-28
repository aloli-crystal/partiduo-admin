# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Clôture du lot A (relecture), côté administration : ordre des pièces,
# double validation et compte rendu atomiques, rejeu, envoi du lien
# d'invitation, restauration en instance neuve.

# Courriel impossible (serveur SMTP en panne).
private class FailingBackend < Marten::Emailing::Backend::Base
  def deliver(email : Marten::Emailing::Email)
    raise IO::Error.new("SMTP injoignable")
  end
end

private def with_failing_mail(&)
  previous = Marten.settings.emailing.backend
  Marten.settings.emailing.backend = FailingBackend.new
  begin
    yield
  ensure
    Marten.settings.emailing.backend = previous
  end
end

private def running(task : PartiduoAdmin::Task) : PartiduoAdmin::Task
  task.state = "running"
  task.save!
  task
end

private def finish_call(task : PartiduoAdmin::Task, token : String, body : Hash) : Marten::HTTP::Response
  headers = {"Content-Type" => "application/json", "Host" => "127.0.0.1", "Authorization" => "Bearer #{token}"}
  Marten::Spec::Client.new.post("/api/agent/v1/tasks/#{task.pk}/finish", data: body.to_json,
    content_type: "application/json", headers: headers)
end

describe "Administration : ordre des pièces (D-AFN-006)" do
  it "retire les extensions avant les modules et ajoute les modules avant les extensions" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    dossier.extensions = "einvoicing"
    dossier.save!
    root = AdminSpec.super_admin
    task = PartiduoAdmin::Fleet.change_modules(root, dossier, ["accounting"], [] of String).value!
    task.params_json["disable"].as_a.map(&.as_s).should eq(["einvoicing", "invoicing"])

    other = AdminSpec.dossier(firm, server)
    task = PartiduoAdmin::Fleet.change_modules(root, other, ["accounting", "invoicing", "stock"], ["einvoicing"]).value!
    task.params_json["enable"].as_a.map(&.as_s).should eq(["stock", "einvoicing"])
  end
end

describe "Administration : double validation et compte rendu atomiques (D-AFN-010, D-AFN-011)" do
  it "ne crée qu'une tâche quand deux personnes valident la même demande en même temps" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    approval = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti").value!
    first = PartiduoAdmin::Approval.get!(id: approval.pk)
    second = PartiduoAdmin::Approval.get!(id: approval.pk)
    PartiduoAdmin::Approvals.approve(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm), first).ok?.should be_true
    late = PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, second)
    late.errors["base"].should eq(["admin.errors.approval.state"])
    PartiduoAdmin::Task.filter(kind: "instance.admin_invite").count.should eq(1)
    approval.reload.state.should eq("approved")
  end

  it "refuse de rejouer une tâche soumise à double validation" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    root = AdminSpec.super_admin
    %w[instance.admin_invite instance.delete].each do |kind|
      task = PartiduoAdmin::Tasks.enqueue(kind, server, PartiduoAdmin::Tasks.dossier_params(dossier), root, dossier)
      task.state = "failed"
      task.save!
      PartiduoAdmin::Tasks.retryable?(task).should be_false
      PartiduoAdmin::Tasks.retry(root, task).should be_false
      task.reload.state.should eq("failed")
    end
  end

  it "n'applique qu'une fois les effets de deux comptes rendus concurrents" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    task = running(PartiduoAdmin::Fleet.backup_now(AdminSpec.super_admin, dossier).value!)
    first = PartiduoAdmin::Task.get!(id: task.pk)
    second = PartiduoAdmin::Task.get!(id: task.pk)
    data = {"path" => "/var/backups/partiduo/x/b.dump", "sha256" => "0" * 64}
    result = JSON.parse(data.to_json)
    PartiduoAdmin::Tasks.finish(first, true, result, "", Array(String).new, SPEC_NOW).should be_true
    PartiduoAdmin::Tasks.finish(second, true, result, "", Array(String).new, SPEC_NOW).should be_false
    second.state.should eq("succeeded")
    PartiduoAdmin::Backup.filter(dossier_id: dossier.pk).count.should eq(1)
  end
end

describe "Administration : lien d'invitation jamais perdu (D-AFN-008)" do
  it "n'enregistre rien et ouvre une alerte quand le courriel échoue, puis applique le compte rendu rejoué" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    root = AdminSpec.super_admin
    input = PartiduoAdmin::Fleet::DossierInput.new(slug: "courriel", label: "Courriel SARL", regime: "fr",
      admin_email: "patron@courriel.fr", server_id: PartiduoAdmin.id?(server.pk), firm_id: PartiduoAdmin.id?(firm.pk),
      payer_id: PartiduoAdmin.id?(AdminSpec.payer(firm).pk))
    dossier = PartiduoAdmin::Fleet.create_dossier(root, input).value!
    task = running(PartiduoAdmin::Task.get!(dossier_id: dossier.pk))
    body = {"ok" => true, "error" => "", "lines" => ["fait"],
            "result" => {"database" => "partiduo_adm_courriel", "version" => "0.1.0",
                         "invitation_url" => "https://courriel.partiduo.localhost/invitation/SECRET"}}

    with_failing_mail do
      response = finish_call(task, token, body)
      response.status.should eq(503)
    end
    task.reload.state.should eq("running")
    task.result.to_s.should eq("")
    dossier.reload.state.should eq("creating")
    PartiduoAdmin::Alert.filter(kind: "mail_failed", dossier_id: dossier.pk, resolved_at__isnull: true).exists?.should be_true

    # L'exécutant a gardé le lien : son compte rendu rejoué passe.
    finish_call(task, token, body).status.should eq(200)
    task.reload.state.should eq("succeeded")
    task.result.to_s.should_not contain("SECRET")
    dossier.reload.state.should eq("active")
    Marten::Spec.delivered_emails.last.text_body.to_s.should contain("/invitation/SECRET")
  end
end

describe "Administration : restauration en instance neuve (D-AFN-009)" do
  it "vérifie le quota Let's Encrypt, compte le certificat émis et passe la copie en erreur si l'installation échoue" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server("srv-quota", "compta.example")
    dossier = AdminSpec.dossier(firm, server)
    AdminSpec.backup(dossier)
    root = AdminSpec.super_admin
    PartiduoAdmin::Config::LE_WEEKLY_LIMIT.times do
      PartiduoAdmin::CertificateIssue.create!(dossier: dossier, host: dossier.host, domain: "compta.example",
        staging: false, issued_at: SPEC_NOW - 1.hour)
    end
    refused = PartiduoAdmin::Fleet.restore(root, dossier, SPEC_NOW, "new", "copie-quota")
    refused.errors["base"].should eq(["admin.errors.dossier.quota"])
    PartiduoAdmin::Dossier.filter(slug: "copie-quota").exists?.should be_false
    PartiduoAdmin::CertificateIssue.all.delete

    task = running(PartiduoAdmin::Fleet.restore(root, dossier, SPEC_NOW, "new", "copie-a").value!)
    PartiduoAdmin::Tasks.finish(task, true, JSON.parse({"database" => "partiduo_copie_a", "version" => "0.1.0",
                                                        "certificate" => {"issued" => true, "staging" => false}}.to_json), "", Array(String).new, SPEC_NOW)
    copy = PartiduoAdmin::Dossier.get!(slug: "copie-a")
    copy.state.should eq("active")
    PartiduoAdmin::CertificateIssue.filter(dossier_id: copy.pk).count.should eq(1)

    task = running(PartiduoAdmin::Fleet.restore(root, dossier, SPEC_NOW, "new", "copie-b").value!)
    PartiduoAdmin::Tasks.finish(task, false, JSON.parse("{}"), "installation échouée", Array(String).new, SPEC_NOW)
    PartiduoAdmin::Dossier.get!(slug: "copie-b").state.should eq("error")
  end
end
