# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"
require "yaml"

private def flatten(node : YAML::Any, prefix : String, into : Set(String)) : Set(String)
  if hash = node.as_h?
    hash.each { |key, value| flatten(value, prefix.empty? ? key.as_s : "#{prefix}.#{key.as_s}", into) }
  else
    into << prefix.sub(/\.(one|other)\z/, "")
  end
  into
end

private def locale_keys(code : String) : Set(String)
  path = File.join(__DIR__, "../../src/admin/locales/#{code}.yml")
  flatten(YAML.parse(File.read(path))[code], "", Set(String).new)
end

describe "Interface de l'administration" do
  it "a les mêmes libellés en français, anglais et néerlandais" do
    fr = locale_keys("fr")
    locale_keys("en").should eq(fr)
    locale_keys("nl").should eq(fr)
  end

  it "a un libellé pour chaque clé citée par le code et les gabarits" do
    fr = locale_keys("fr")
    used = Set(String).new
    Dir.glob(File.join(__DIR__, "../../src/admin/**/*.{cr,html}")).each do |file|
      File.read(file).scan(/["'](admin\.[a-z_.]+[a-z_])["']/) { |match| used << match[1] }
    end
    (used - fr).to_a.sort!.should eq([] of String)
  end

  it "sert la page de connexion dans les trois langues, avec les repères d'accessibilité" do
    {"fr" => "Connexion à l'administration", "en" => "Sign in to the administration", "nl" => "Aanmelden bij het beheer"}.each do |locale, title|
      page = AdminSpec::Browser.new(locale).get("/login")
      page.status.should eq(200)
      page.html.should contain(title)
      page.html.should contain(%(<html lang="#{locale}">))
      page.html.should contain(%(href="#pd-main"))
      page.html.should contain(%(<label class="label" for="pd-email">))
    end
  end

  it "renvoie un anonyme vers la connexion" do
    response = AdminSpec::Browser.new.get("/dossiers")
    response.status.should eq(302)
    response.headers["Location"].should start_with("/login")
  end

  it "montre à chaque rôle sa portée et refuse le reste" do
    server, _ = AdminSpec.server
    north = AdminSpec.firm("Nord")
    south = AdminSpec.firm("Sud")
    a = AdminSpec.dossier(north, server, slug: "nord-a")
    c = AdminSpec.dossier(south, server, slug: "sud-c")
    manager = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, north)
    PartiduoAdmin::Assignment.create!(user: manager, dossier: a)

    browser = AdminSpec::Browser.new(token: AdminSpec.session(manager))
    list = browser.get("/dossiers").html
    list.should contain("nord-a")
    list.should_not contain("sud-c")
    browser.get("/dossiers/#{c.pk}").status.should eq(403)
    browser.get("/users").status.should eq(403)
    browser.get("/servers").status.should eq(403)
    detail = browser.get("/dossiers/#{a.pk}").html
    detail.should contain("Sauvegarder")
    detail.should_not contain("Archiver")

    admin = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)))
    admin.get("/dossiers/#{a.pk}").html.should contain("Archiver")
    admin.get("/firms").status.should eq(403)
  end

  it "crée un dossier par le formulaire et refuse sans donneur d'ordre" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    payer = AdminSpec.payer(firm)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)))
    form = browser.get("/dossiers/new")
    form.status.should eq(200)
    form.html.should contain(%(<legend>Modules))
    data = {"slug" => "formulaire", "label" => "Formulaire SAS", "regime" => "fr", "locale" => "fr",
            "modules" => ["accounting", "invoicing"], "admin_email" => "gerant@formulaire.fr",
            "server_id" => server.pk.to_s, "payer_id" => "", "backup_schedule" => "daily", "backup_retention_days" => "30"}
    refused = browser.post("/dossiers/new", data)
    refused.status.should eq(422)
    refused.html.should contain("Le donneur d'ordre est obligatoire.")
    refused.html.should contain(%(aria-invalid="true"))
    created = browser.post("/dossiers/new", data.merge({"payer_id" => payer.pk.to_s}))
    created.status.should eq(302)
    PartiduoAdmin::Dossier.get!(slug: "formulaire").payer_id.should eq(payer.pk)
    # Sans choix : le paquet de production.
    PartiduoAdmin::Dossier.get!(slug: "formulaire").package.should eq("app")
  end

  it "choisit le paquet à la création et l'affiche sur la fiche et dans la liste" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    payer = AdminSpec.payer(firm)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)))
    form = browser.get("/dossiers/new").html
    form.should contain(%(name="package"))
    form.should contain("partiduo-app (production)")
    form.should contain("partiduo-app-devel (développement)")
    form.should_not contain(%(name="version"))
    data = {"slug" => "essai-devel", "label" => "Essai SAS", "regime" => "fr", "locale" => "fr",
            "modules" => ["accounting"], "admin_email" => "gerant@essai.fr", "server_id" => server.pk.to_s,
            "payer_id" => payer.pk.to_s, "package" => "beta", "backup_schedule" => "daily", "backup_retention_days" => "30"}
    refused = browser.post("/dossiers/new", data)
    refused.status.should eq(422)
    refused.html.should contain("Paquet inconnu")
    browser.post("/dossiers/new", data.merge({"package" => "devel"})).status.should eq(302)
    dossier = PartiduoAdmin::Dossier.get!(slug: "essai-devel")
    dossier.package.should eq("devel")
    PartiduoAdmin::Task.get!(dossier_id: dossier.pk).params_json["package"].should eq("devel")
    browser.get("/dossiers/#{dossier.pk}").html.should contain("partiduo-app-devel (développement)")
    browser.get("/dossiers").html.should contain("partiduo-app-devel")
  end

  it "ne propose plus de versions ni de vagues" do
    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.super_admin))
    browser.get("/").html.should_not contain(%(href="/releases"))
    %w[/releases /waves].each do |path|
      expect_raises(Marten::Routing::Errors::NoResolveMatch) { Marten.routes.resolve(path) }
    end
  end

  it "exporte les dossiers par donneur d'ordre en CSV, dans la portée" do
    server, _ = AdminSpec.server
    north = AdminSpec.firm("Nord")
    south = AdminSpec.firm("Sud")
    payer = AdminSpec.payer(north, "other", "=Payeur Malin")
    AdminSpec.dossier(north, server, slug: "facture-a", payer: payer)
    AdminSpec.dossier(south, server, slug: "facture-b")
    browser = AdminSpec::Browser.new(token: AdminSpec.session(AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, north)))
    view = browser.get("/payers/dossiers")
    view.status.should eq(200)
    view.html.should contain("facture-a")
    csv = browser.get("/payers/dossiers?format=csv")
    csv.content_type.should contain("text/csv")
    rows = CSV.parse(csv.content)
    rows.first.first(3).should eq(%w[payer_id payer_kind payer_name])
    rows.size.should eq(2)
    rows[1][2].should eq("'=Payeur Malin")
    rows[1][12].should eq("facture-a")
  end

  it "affiche le jeton d'un nouveau serveur une seule fois, au super-admin" do
    root = AdminSpec.super_admin
    browser = AdminSpec::Browser.new(token: AdminSpec.session(root))
    page = browser.post("/servers", {"name" => "hote1", "hostname" => "hote1.partiduo.app", "domain" => "partiduo.app"})
    page.status.should eq(200)
    token = page.html.match!(/<p class="pd-token mb-3">([^<]+)<\/p>/)[1]
    PartiduoAdmin::Directory.server_for_token(token).try(&.name).should eq("hote1")
    browser.get("/servers").html.should_not contain(token)
  end

  it "rend tous les écrans principaux sans erreur pour le super-admin" do
    firm = AdminSpec.firm
    server, _ = AdminSpec.server
    dossier = AdminSpec.dossier(firm, server)
    AdminSpec.backup(dossier)
    task = PartiduoAdmin::Fleet.backup_now(nil, dossier).value!
    browser = AdminSpec::Browser.new("en", token: AdminSpec.session(AdminSpec.super_admin))
    ["/", "/dossiers", "/dossiers/#{dossier.pk}", "/dossiers/#{dossier.pk}/modules", "/dossiers/new", "/approvals",
     "/tasks", "/tasks/#{task.pk}", "/alerts", "/audit", "/payers", "/payers/new", "/payers/dossiers", "/firms",
     "/users", "/users/new", "/servers", "/account"].each do |path|
      response = browser.get(path)
      {path, response.status}.should eq({path, 200})
    end
  end
end

describe "Licence" do
  it "ouvre chaque fichier source Crystal par l'en-tête SPDX" do
    root = File.join(__DIR__, "../..")
    files = Dir.glob(["src/**/*.cr", "spec/**/*.cr", "config/**/*.cr", "manage.cr"].map { |glob| File.join(root, glob) })
    missing = files.reject { |file| File.read_lines(file).first? == "# SPDX-License-Identifier: AGPL-3.0-or-later" }
    missing.should eq([] of String)
  end
end
