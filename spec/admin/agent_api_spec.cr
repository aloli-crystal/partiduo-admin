# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

private def api(path : String, token : String?, body = {} of String => String) : Marten::HTTP::Response
  headers = {"Content-Type" => "application/json", "Host" => "127.0.0.1"}
  headers["Authorization"] = "Bearer #{token}" if token
  Marten::Spec::Client.new.post(path, data: body.to_json, content_type: "application/json", headers: headers)
end

describe "API de l'exécutant" do
  it "refuse un appel sans jeton ou avec un jeton inconnu" do
    api("/api/agent/v1/claim", nil).status.should eq(401)
    api("/api/agent/v1/claim", "faux").status.should eq(401)
  end

  it "remet ses tâches à l'exécutant du serveur, reçoit journal et compte rendu" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    _, other_token = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    task = PartiduoAdmin::Fleet.backup_now(nil, dossier).value!

    empty = JSON.parse(api("/api/agent/v1/claim", other_token).content)
    empty["task"].raw.should be_nil

    claimed = JSON.parse(api("/api/agent/v1/claim", token).content)
    claimed["task"]["id"].as_i64.should eq(task.pk)
    claimed["task"]["kind"].should eq("backup.run")
    claimed["task"]["params"]["slug"].should eq(dossier.slug)
    task.reload.state.should eq("running")
    server.reload.last_seen_at.should_not be_nil

    api("/api/agent/v1/tasks/#{task.pk}/log", other_token, {"lines" => ["intrus"]}).status.should eq(404)
    api("/api/agent/v1/tasks/#{task.pk}/log", token, {"lines" => ["pg_dump fait"]}).status.should eq(200)
    task.reload.log.to_s.should contain("pg_dump fait")

    result = {"path" => "/var/backups/partiduo/x.dump", "media_path" => "", "size_bytes" => 1234, "sha256" => "b" * 64,
              "taken_at" => SPEC_NOW.to_rfc3339}
    api("/api/agent/v1/tasks/#{task.pk}/finish", token, {"ok" => true, "result" => result, "lines" => ["fin"]}).status.should eq(200)
    task.reload.state.should eq("succeeded")
    backup = PartiduoAdmin::Backup.get!(dossier_id: dossier.pk)
    backup.size_bytes.should eq(1234)
    backup.state.should eq("done")
    # Compte rendu rejoué après une coupure : sans effet.
    api("/api/agent/v1/tasks/#{task.pk}/finish", token, {"ok" => false, "error" => "rejoué"}).status.should eq(200)
    task.reload.state.should eq("succeeded")
    PartiduoAdmin::Backup.filter(dossier_id: dossier.pk).count.should eq(1)
  end

  it "reprend une tâche dont le bail a expiré (coupure de l'exécutant)" do
    firm = AdminSpec.firm
    server, token = AdminSpec.server
    task = PartiduoAdmin::Fleet.backup_now(nil, AdminSpec.dossier(firm, server)).value!
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW - 1.hour).try(&.pk).should eq(task.pk)
    PartiduoAdmin::Tasks.claim(server, SPEC_NOW - 1.hour + 1.minute).should be_nil
    resumed = JSON.parse(api("/api/agent/v1/claim", token).content)
    resumed["task"]["id"].as_i64.should eq(task.pk)
    resumed["task"]["attempt"].as_i.should eq(2)
  end

  it "dédoublonne une tâche identique encore en attente" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    first = PartiduoAdmin::Fleet.backup_now(nil, dossier).value!
    PartiduoAdmin::Fleet.backup_now(nil, dossier).value!.pk.should eq(first.pk)
  end
end
