# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

private def setup_fleet
  server, _ = AdminSpec.server
  north = AdminSpec.firm("Nord")
  south = AdminSpec.firm("Sud")
  a = AdminSpec.dossier(north, server, slug: "nord-a")
  b = AdminSpec.dossier(north, server, slug: "nord-b")
  c = AdminSpec.dossier(south, server, slug: "sud-c")
  {north, south, a, b, c}
end

describe PartiduoAdmin::Access do
  it "donne tout le parc au super-admin" do
    _, _, a, b, c = setup_fleet
    root = AdminSpec.super_admin
    PartiduoAdmin::Access.dossiers(root).map(&.slug.to_s).sort!.should eq(%w[nord-a nord-b sud-c])
    PartiduoAdmin::Access.fleet?(root).should be_true
    {a, b, c}.each { |dossier| PartiduoAdmin::Access.can?(root, :archive, dossier).should be_true }
  end

  it "limite l'admin de cabinet aux dossiers de son cabinet" do
    north, _, a, _, c = setup_fleet
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    PartiduoAdmin::Access.dossiers(admin).map(&.slug.to_s).sort!.should eq(%w[nord-a nord-b])
    PartiduoAdmin::Access.can?(admin, :archive, a).should be_true
    PartiduoAdmin::Access.can?(admin, :view, c).should be_false
    PartiduoAdmin::Access.fleet?(admin).should be_false
    PartiduoAdmin::Access.can_create_dossier?(admin, north.pk).should be_true
    PartiduoAdmin::Access.assignable_roles(admin).should_not contain(PartiduoAdmin::Config::SUPER_ADMIN)
  end

  it "limite le gestionnaire aux dossiers confiés et à la gestion courante" do
    north, _, a, b, _ = setup_fleet
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, north)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: a)
    PartiduoAdmin::Access.dossiers(manager).map(&.slug).should eq(%w[nord-a])
    PartiduoAdmin::Access.can?(manager, :modules, a).should be_true
    PartiduoAdmin::Access.can?(manager, :backup, a).should be_true
    PartiduoAdmin::Access.can?(manager, :request_admin_invite, a).should be_true
    PartiduoAdmin::Access.can?(manager, :archive, a).should be_false
    PartiduoAdmin::Access.can?(manager, :suspend, a).should be_false
    PartiduoAdmin::Access.can?(manager, :view, b).should be_false
    PartiduoAdmin::Access.can_create_dossier?(manager, north.pk).should be_false
    PartiduoAdmin::Access.assignable_roles(manager).should be_empty
    PartiduoAdmin::Access.can_view_audit?(manager).should be_false
  end

  it "réserve la validation à une autre personne habilitée" do
    north, south, a, _, _ = setup_fleet
    requester = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    colleague = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, north)
    stranger = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, south)
    approval = PartiduoAdmin::Approval.create!(kind: "admin_invite", reference: "DV-TEST-0001", dossier: a, reason: "perte d'accès",
      requested_by: requester, expires_at: SPEC_NOW + 1.day)
    PartiduoAdmin::Access.can_approve?(requester, approval).should be_false
    PartiduoAdmin::Access.can_approve?(colleague, approval).should be_true
    PartiduoAdmin::Access.can_approve?(manager, approval).should be_false
    PartiduoAdmin::Access.can_approve?(stranger, approval).should be_false
    PartiduoAdmin::Access.can_approve?(AdminSpec.super_admin, approval).should be_true
  end

  it "cloisonne utilisateurs, donneurs d'ordre et journal d'audit par cabinet" do
    north, south, _, _, _ = setup_fleet
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)
    other = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, south)
    PartiduoAdmin::Access.users(admin).map(&.pk).should_not contain(other.pk)
    PartiduoAdmin::Access.can_manage_user?(admin, other).should be_false
    PartiduoAdmin::Access.payers(admin).all?(&.firm_id.==(north.pk)).should be_true
    PartiduoAdmin::Access.can_manage_payer?(admin, south.pk).should be_false
    PartiduoAdmin::Audit.log(other, "spec.sud")
    PartiduoAdmin::Access.audit(admin).map(&.action).should_not contain("spec.sud")
  end
end
