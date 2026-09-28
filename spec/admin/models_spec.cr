# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

describe "Modèles de l'administration" do
  it "tient le journal d'audit en ajout seul (déclencheur)" do
    entry = PartiduoAdmin::Audit.log(nil, "spec.test", actor_label: "spec")
    expect_raises(Exception, /ajout seul/) do
      PartiduoAdmin::AuditEntry.filter(id: entry.pk).update(action: "falsifié")
    end
    expect_raises(Exception, /ajout seul/) do
      PartiduoAdmin::AuditEntry.filter(id: entry.pk).delete
    end
    PartiduoAdmin::AuditEntry.get!(id: entry.pk).action.should eq("spec.test")
  end

  it "exige un donneur d'ordre pour tout dossier (contrainte en base)" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    expect_raises(Exception) do
      PartiduoAdmin::Dossier.create!(slug: "sans-payeur", label: "X", regime: "fr", admin_email: "a@b.fr",
        server: server, firm: firm)
    end
  end

  it "rattache un donneur d'ordre à un cabinet et compose son adresse de facturation" do
    firm = AdminSpec.firm("Cabinet Nord")
    payer = AdminSpec.payer(firm, "firm", "Cabinet Nord")
    payer.billing_address.should eq("1 rue de la Paix, 75002 Paris, FR")
    payer.firm_name.should eq("Cabinet Nord")
  end

  it "valide le SIREN par la clé de Luhn" do
    PartiduoAdmin::Siren.valid?("732829320").should be_true
    PartiduoAdmin::Siren.valid?("732829321").should be_false
    PartiduoAdmin::Siren.valid?("12345").should be_false
  end

  it "applique la règle de sous-domaine de partiduo-provision et nomme les bases" do
    PartiduoAdmin::Protocol.valid_slug?("demo-fr").should be_true
    PartiduoAdmin::Protocol.valid_slug?("Demo").should be_false
    PartiduoAdmin::Protocol.valid_slug?("demo-").should be_false
    PartiduoAdmin::Protocol.valid_slug?("1demo").should be_false
    PartiduoAdmin::Protocol.database_for("demo-fr").should eq("partiduo_demo_fr")
    PartiduoAdmin::Protocol.database_for("demo-fr", local: true).should eq("partiduo_adm_demo_fr")
  end

  it "ferme la liste des types de tâches" do
    PartiduoAdmin::Protocol.valid_kind?("backup.run").should be_true
    PartiduoAdmin::Protocol.valid_kind?("shell.exec").should be_false
    server, _ = AdminSpec.server
    expect_raises(ArgumentError) do
      PartiduoAdmin::Tasks.enqueue("shell.exec", server, {} of String => JSON::Any)
    end
  end
end
