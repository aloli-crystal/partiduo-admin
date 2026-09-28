# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

private def login(browser, email, password = AdminSpec::PASSWORD)
  browser.post("/login", {"email" => email, "password" => password, "next" => "/"})
end

describe "Authentification de l'administration" do
  it "exige le second facteur des rôles autres que super-admin (niveau 2)" do
    user = AdminSpec.user(totp: false)
    browser = AdminSpec::Browser.new
    response = login(browser, user.email.to_s)
    response.status.should eq(302)
    response.headers["Location"].should eq("/account")
    browser.get("/dossiers").headers["Location"].should eq("/account")

    # Enrôlement du TOTP : la session monte au niveau 2.
    browser.post("/account/totp", {"command" => "begin"})
    user.reload
    code = TOTP::Authenticator.from_base32(user.totp_pending_secret.to_s).at(SPEC_NOW)
    page = browser.post("/account/totp", {"code" => code})
    page.status.should eq(200)
    page.html.should contain("Codes de récupération")
    browser.get("/dossiers").status.should eq(200)
  end

  it "connecte par mot de passe puis code TOTP, refuse le rejeu et accepte un code de récupération une fois" do
    user = AdminSpec.user
    codes = PartiduoAdmin::Auth::RecoveryCodes.generate(user)
    browser = AdminSpec::Browser.new
    login(browser, user.email.to_s).headers["Location"].should start_with("/login/second-factor")
    code = AdminSpec.totp_code(user, SPEC_NOW)
    browser.post("/login/second-factor", {"code" => code, "next" => "/"}).headers["Location"].should eq("/")
    browser.get("/").status.should eq(200)

    replay = AdminSpec::Browser.new
    login(replay, user.email.to_s)
    replay.post("/login/second-factor", {"code" => code}).status.should eq(422)

    recovery = AdminSpec::Browser.new
    login(recovery, user.email.to_s)
    recovery.post("/login/second-factor", {"code" => codes.first.downcase}).status.should eq(302)
    again = AdminSpec::Browser.new
    login(again, user.email.to_s)
    again.post("/login/second-factor", {"code" => codes.first}).status.should eq(422)
  end

  it "limite les tentatives : temporisation puis blocage au dixième échec" do
    user = AdminSpec.user
    3.times { PartiduoAdmin::Auth.login_password(user.email.to_s, "mauvais", now: SPEC_NOW).error.should eq("admin.errors.login.invalid") }
    waiting = PartiduoAdmin::Auth.login_password(user.email.to_s, AdminSpec::PASSWORD, now: SPEC_NOW)
    waiting.error.should eq("admin.errors.login.wait")
    time = SPEC_NOW
    7.times do
      time += 20.minutes
      PartiduoAdmin::Auth.login_password(user.email.to_s, "mauvais", now: time)
    end
    user.reload.locked?.should be_true
    PartiduoAdmin::Auth.login_password(user.email.to_s, AdminSpec::PASSWORD, now: time + 1.hour).error.should eq("admin.errors.login.locked")
  end

  it "exige une passkey du super-admin : le niveau 2 ne suffit pas" do
    root = PartiduoAdmin::User.create!(email: "root@example.com", role: PartiduoAdmin::Config::SUPER_ADMIN)
    browser = AdminSpec::Browser.new(token: AdminSpec.session(root, 2))
    browser.get("/").headers["Location"].should eq("/account")
    browser.post("/account/password", {"password" => AdminSpec::PASSWORD, "confirmation" => AdminSpec::PASSWORD}).status.should eq(403)
  end

  it "amorce le premier super-admin par invitation, qui enrôle sa passkey et se connecte au niveau 3" do
    stdout = IO::Memory.new
    command = PartiduoAdmin::Commands::Bootstrap.new(["--email=chef@aloli.fr", "--first-name=Philippe"],
      stdout: stdout, stderr: IO::Memory.new, exit_raises: true)
    command.handle.should eq(0)
    link = stdout.to_s.match!(/\/invitation\/(\S+)/)[1]
    root = PartiduoAdmin::User.get!(email: "chef@aloli.fr")
    root.super_admin?.should be_true
    # Un second amorçage est refusé.
    PartiduoAdmin::Commands::Bootstrap.new(["--email=autre@aloli.fr"], stdout: IO::Memory.new,
      stderr: IO::Memory.new, exit_raises: true).handle.should eq(1)

    browser = AdminSpec::Browser.new
    browser.get("/invitation/#{link}").status.should eq(200)
    browser.post("/invitation/#{link}").headers["Location"].should eq("/account")
    browser.get("/").headers["Location"].should eq("/account")
    browser.get("/invitation/#{link}").status.should eq(404)

    authenticator = AdminSpec::Authenticator.new
    options = browser.post("/account/passkey/options").content
    registered = JSON.parse(browser.post("/account/passkey", authenticator.register(options)).content)
    registered["ok"].as_bool.should be_true
    PartiduoAdmin::Auth::RecoveryCodes.remaining(root).should eq(10)

    elevation = browser.post("/account/elevate/options").content
    JSON.parse(browser.post("/account/elevate", authenticator.assert(elevation)).content)["ok"].as_bool.should be_true
    browser.get("/").status.should eq(200)

    fresh = AdminSpec::Browser.new
    login_options = fresh.post("/login/passkey/options").content
    logged = JSON.parse(fresh.post("/login/passkey", authenticator.assert(login_options).merge({"next" => "/servers"})).content)
    logged["redirect"].should eq("/servers")
    fresh.get("/servers").status.should eq(200)
    PartiduoAdmin::Session.filter(user_id: root.pk, level: 3).count.should eq(2)
  end

  it "réinvite un utilisateur qui a perdu ses moyens : secrets et sessions révoqués" do
    firm = AdminSpec.firm
    admin = AdminSpec.user(PartiduoAdmin::Config::FIRM_ADMIN, firm)
    lost = AdminSpec.user(PartiduoAdmin::Config::FILE_MANAGER, firm)
    token = AdminSpec.session(lost)
    PartiduoAdmin::Directory.reinvite(admin, lost).should be_true
    lost.reload.totp_enabled?.should be_false
    PartiduoAdmin::Auth::Sessions.find(token, SPEC_NOW).should be_nil
    Marten::Spec.delivered_emails.last.to.map(&.address).should eq([lost.email])
    PartiduoAdmin::Directory.reinvite(lost, admin).should be_false
  end
end
