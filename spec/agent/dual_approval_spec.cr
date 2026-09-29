# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Validation à deux au choix, côté exécutant (D-VAL2-005) : le mode reçu
# (`approval_mode`) et les personnes doivent concorder ; il est écrit au
# journal de la tâche et, pour un recours d'accès, dans celui du dossier.

private def params(slug = "garde", **extra) : Hash(String, JSON::Any)
  base = JSON.parse({"slug" => slug, "host" => "#{slug}.partiduo.localhost", "domain" => "partiduo.localhost",
                     "database" => "", "modules" => ["accounting", "invoicing"], "extensions" => [] of String,
                     "version" => "0.1.0", "locale" => "fr"}.to_json).as_h
  extra.each { |key, value| base[key.to_s] = JSON.parse(value.to_json) }
  base
end

private def run_dry(admin : AdminSpec::FakeAdmin, id : Int64, kind : String, task_params : Hash,
                    archive : String? = nil, config = admin.config) : {JSON::Any, PartiduoAgent::DrySystem}
  admin.push(id, kind, task_params)
  runner = PartiduoAgent::Runner.new(config)
  dry = runner.build_system(->(_line : String) { nil }).as(PartiduoAgent::DrySystem)
  dry.databases << "partiduo_adm_garde"
  dry.provisioned << "partiduo_adm_garde"
  dry.files[archive] = 1_i64 if archive
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

describe "partiduo-agent : mode de validation des opérations sensibles (D-VAL2-005)" do
  it "recours d'accès à une personne : un seul nom, et la marque « une personne » pour l'instance" do
    with_admin do |admin|
      report, dry = run_dry(admin, 900_i64, "instance.admin_invite",
        params(email: "gerant@demo.fr", reason: "gérant parti", approval_ref: "DV-1", approval_mode: "single",
          approvers: ["seule@cabinet.fr"]))
      report["ok"].as_bool.should be_true
      call = dry.calls.find!(&.starts_with?("instance admin-invite"))
      call.should contain("--approvers seule@cabinet.fr,#{PartiduoAdmin::Protocol::SINGLE_APPROVER_MARK}")
      admin.logs[900_i64].join('\n').should contain("validation à une personne DV-1 par seule@cabinet.fr")
    end
  end

  it "recours d'accès à deux personnes : inchangé, les deux noms transmis" do
    with_admin do |admin|
      report, dry = run_dry(admin, 901_i64, "instance.admin_invite",
        params(email: "gerant@demo.fr", reason: "gérant parti", approval_ref: "DV-2", approval_mode: "dual",
          approvers: ["a@x.fr", "b@x.fr"]))
      report["ok"].as_bool.should be_true
      dry.calls.find!(&.starts_with?("instance admin-invite")).should contain("--approvers a@x.fr,b@x.fr")
      admin.logs[901_i64].join('\n').should contain("validation à deux personnes DV-2")
    end
  end

  it "refuse un mode et des personnes qui ne concordent pas, ou un mode inconnu" do
    with_admin do |admin|
      [
        params(email: "g@demo.fr", reason: "motif", approval_ref: "DV-3", approval_mode: "single", approvers: ["a@x.fr", "b@x.fr"]),
        params(email: "g@demo.fr", reason: "motif", approval_ref: "DV-3", approval_mode: "dual", approvers: ["a@x.fr"]),
        params(email: "g@demo.fr", reason: "motif", approval_ref: "DV-3", approval_mode: "dual", approvers: ["a@x.fr", "A@x.fr"]),
        # Sans mode (administration antérieure) : deux personnes exigées.
        params(email: "g@demo.fr", reason: "motif", approval_ref: "DV-3", approvers: ["a@x.fr"]),
        params(email: "g@demo.fr", reason: "motif", approval_ref: "DV-3", approval_mode: "none", approvers: ["a@x.fr"]),
      ].each_with_index do |task_params, index|
        report, dry = run_dry(admin, 910_i64 + index, "instance.admin_invite", task_params)
        report["ok"].as_bool.should be_false
        dry.calls.none?(&.starts_with?("instance admin-invite")).should be_true
      end
    end
  end

  it "suppression définitive à une personne : même durée légale revérifiée, mode au journal" do
    with_admin do |admin|
      config = admin.config
      archive = File.join(config.backup_dir, "garde", "archive-20160101T000000Z.dump")
      report, dry = run_dry(admin, 920_i64, "instance.delete",
        params(approval_ref: "DV-4", approval_mode: "single", approvers: ["seule@cabinet.fr"], backups: [archive]), archive, config)
      report["ok"].as_bool.should be_true
      dry.calls.should contain("dropdb partiduo_adm_garde")
      admin.logs[920_i64].join('\n').should contain("suppression définitive — validation à une personne DV-4 par seule@cabinet.fr")

      # Archive récente : refus du serveur, quel que soit le mode (D-CRA-007).
      young = File.join(config.backup_dir, "garde", "archive-#{Time.utc.to_s("%Y%m%dT%H%M%SZ")}.dump")
      refused, dry = run_dry(admin, 921_i64, "instance.delete",
        params(approval_ref: "DV-5", approval_mode: "single", approvers: ["seule@cabinet.fr"], backups: [young]), young, config)
      refused["ok"].as_bool.should be_false
      refused["error"].as_s.should contain("durée légale")
      dry.calls.none?(&.starts_with?("dropdb")).should be_true
    end
  end

  it "suppression définitive : refusée avant tout geste si les personnes ne concordent pas avec le mode" do
    with_admin do |admin|
      config = admin.config
      archive = File.join(config.backup_dir, "garde", "archive-20160101T000000Z.dump")
      report, dry = run_dry(admin, 930_i64, "instance.delete",
        params(approval_ref: "DV-6", approval_mode: "dual", approvers: ["seul@cabinet.fr"], backups: [archive]), archive, config)
      report["error"].as_s.should contain("validation à deux personnes incomplète")
      report["ok"].as_bool.should be_false
      dry.calls.none? { |call| call.starts_with?("dropdb") || call.starts_with?("remove") }.should be_true
    end
  end
end
