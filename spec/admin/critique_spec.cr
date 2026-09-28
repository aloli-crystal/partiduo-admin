# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Critique de complétude du lot A (D-CRA-003, D-CRA-006).

describe "Double validation : rejet conditionnel (D-AFN-011, D-CRA-006)" do
  it "ne rejette pas une demande validée entre-temps" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    approval = PartiduoAdmin::Approvals.request_admin_invite(requester, dossier, "gerant@demo.fr", "gérant parti").value!
    stale = PartiduoAdmin::Approval.get!(id: approval.pk)
    PartiduoAdmin::Approvals.approve(AdminSpec.super_admin, approval).value!
    PartiduoAdmin::Approvals.reject(requester, stale).should be_false
    stale.state.should eq("approved")
    PartiduoAdmin::Approval.get!(id: approval.pk).state.should eq("approved")
  end
end

describe "Recours d'accès : paramètres de la tâche (D-CRA-003)" do
  it "porte la langue du dossier pour le courriel remis par le serveur" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    PartiduoAdmin::Tasks.dossier_params(dossier)["locale"].as_s.should eq(dossier.locale.to_s)
  end
end
