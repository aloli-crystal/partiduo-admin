# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Défauts relevés par la vérification de bout en bout au navigateur
# (A:bout-en-bout, D-ABE-001 à D-ABE-004) : une chaîne vide est vraie dans
# un gabarit de Marten.
describe "Interface de l'administration : vérification de bout en bout" do
  it "propose d'activer l'application d'authentification tant qu'aucun secret n'est en attente" do
    user = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, totp: false)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(user, 1))
    page = browser.get("/account").html
    page.should contain("Activer une application d'authentification")
    page.should_not contain(%(<p class="pd-token mb-2"></p>))

    browser.post("/account/totp", {"command" => "begin"}).status.should eq(302)
    secret = PartiduoAdmin::User.get!(id: user.pk).totp_pending_secret || fail("secret en attente absent")
    page = browser.get("/account").html
    page.should contain(%(<p class="pd-token mb-2">#{secret}</p>))
    page.should_not contain("Activer une application d'authentification")
  end

  it "traduit la planification et les états relevés, et n'affiche pas d'erreur vide" do
    server, _ = AdminSpec.server
    firm = AdminSpec.firm
    dossier = AdminSpec.dossier(firm, server, slug: "releve")
    dossier.service_state = "stopped"
    dossier.database_state = "ok"
    dossier.save!
    PartiduoAdmin::Alert.create!(kind: "service", severity: "danger", dossier: dossier, detail: "stopped", opened_at: SPEC_NOW)
    task = PartiduoAdmin::Task.create!(kind: "backup.run", dossier: dossier, server: server, state: "succeeded")

    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)))
    page = browser.get("/dossiers/#{dossier.pk}").html
    page.should contain("quotidienne · 30 j")
    page.should contain("<dd>arrêté</dd>")
    page.should contain("<dd>joignable</dd>")
    page.should contain("service arrêté arrêté")
    page.should_not contain("stopped")
    browser.get("/tasks/#{task.pk}").html.should_not contain("<dt>Erreur</dt>")
    task.error = "échec simulé"
    task.save!
    browser.get("/tasks/#{task.pk}").html.should contain("<dt>Erreur</dt><dd>échec simulé</dd>")
  end

  it "n'annonce pas d'aide absente et demande confirmation avant un nouveau jeton" do
    field = PartiduoAdmin::FormField.new("label", "Raison sociale")
    field.help.should be_nil
    field.describedby.should be_nil
    PartiduoAdmin::FormField.new("slug", "Sous-domaine", help: "aide").describedby.should eq("f-slug-help")

    AdminSpec.server
    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.super_admin))
    browser.get("/servers").html.should contain(%(hx-confirm="Un nouveau jeton annule aussitôt))
  end
end

describe "partiduo-agent : échec simulé (--fail-on)" do
  it "n'est permis qu'à blanc" do
    PartiduoAgent::Config.parse(["--token-file", __FILE__, "--admin-url", "http://127.0.0.1:8200",
                                 "--fail-on", "instance migrate"]).fail_on.should eq("instance migrate")
    expect_raises(ArgumentError, /à blanc/) do
      PartiduoAgent::Config.parse(["--token-file", __FILE__, "--admin-url", "http://127.0.0.1:8200",
                                   "--mode", "local", "--fail-on", "migrate"])
    end
  end
end
