# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# L'exécutant (à blanc) contre la vraie API de l'administration, servie par
# Marten sur 127.0.0.1 : parcours complet des tâches, de la file aux effets
# sur l'inventaire.
private def with_admin_server(&)
  server = HTTP::Server.new(Marten::Server.handlers)
  address = server.bind_tcp("127.0.0.1", 0)
  spawn { server.listen }
  Fiber.yield
  begin
    yield "http://127.0.0.1:#{address.port}"
  ensure
    server.close
  end
end

private def drain(runner : PartiduoAgent::Runner) : Int32
  count = 0
  while runner.run_once
    count += 1
    raise "boucle" if count > 20
  end
  count
end

describe "Exécutant contre l'administration" do
  it "crée, sauvegarde, change les modules, archive puis monte de version avec retour arrière" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    PartiduoAdmin::Release.create!(version: "0.1.0")
    input = PartiduoAdmin::Fleet::DossierInput.new(slug: "bout-en-bout", label: "Bout en bout SAS", regime: "fr",
      admin_email: "gerant@bout.fr", server_id: PartiduoAdmin.id?(server.pk), firm_id: PartiduoAdmin.id?(firm.pk),
      payer_id: PartiduoAdmin.id?(AdminSpec.payer(firm).pk), version: "0.1.0")
    dossier = PartiduoAdmin::Fleet.create_dossier(admin, input).value!

    with_admin_server do |url|
      config = PartiduoAgent::Config.new
      config.admin_url = url
      config.token = token
      config.state_dir = File.join(Dir.tempdir, "partiduo-agent-e2e-#{Random::Secure.hex(4)}")
      config.backup_dir = File.join(config.state_dir, "backups")
      runner = PartiduoAgent::Runner.new(config)

      drain(runner).should eq(1)
      dossier.reload
      dossier.state.should eq("active")
      dossier.database.should eq("partiduo_adm_bout_en_bout")
      create = PartiduoAdmin::Task.get!(dossier_id: dossier.pk, kind: "instance.create")
      create.state.should eq("succeeded")
      create.log.to_s.should contain("[à blanc] partiduo-provision")
      server.reload.agent_mode.should eq("dry-run")
      Marten::Spec.delivered_emails.flat_map(&.to).map(&.address).should contain("gerant@bout.fr")

      PartiduoAdmin::Fleet.backup_now(admin, dossier)
      PartiduoAdmin::Fleet.change_modules(admin, dossier, ["accounting"], ["skel"])
      drain(runner).should eq(2)
      PartiduoAdmin::Backup.get!(dossier_id: dossier.pk, kind: "manual").sha256.to_s.size.should eq(64)
      dossier.reload.modules.should eq("accounting")

      # Montée de version : la migration échoue, retour arrière.
      release = PartiduoAdmin::Release.create!(version: "0.2.0")
      config.fail_on = "instance migrate"
      PartiduoAdmin::Fleet.upgrade(admin, dossier, release)
      drain(runner)
      upgrade = PartiduoAdmin::Task.get!(dossier_id: dossier.pk, kind: "instance.upgrade")
      upgrade.state.should eq("failed")
      upgrade.result_json["rolled_back"].as_bool.should be_true
      dossier.reload.version.should eq("0.1.0")
      PartiduoAdmin::Backup.filter(dossier_id: dossier.pk, kind: "pre_upgrade").count.should eq(1)

      # Relance par l'admin : la montée passe.
      PartiduoAdmin::Tasks.retry(admin, upgrade).should be_true
      drain(runner)
      dossier.reload.version.should eq("0.2.0")

      PartiduoAdmin::Fleet.lifecycle(admin, dossier, "archive", "cessation")
      drain(runner)
      dossier.reload.state.should eq("archived")
      PartiduoAdmin::Backup.get!(dossier_id: dossier.pk, kind: "archive").state.should eq("verified")
    end
  end
end
