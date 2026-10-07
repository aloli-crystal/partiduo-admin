# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Connexion : passkey d'abord (niveau 3, exigé du super-admin), mot de
  # passe puis code TOTP ou code de récupération (niveau 2).
  class LoginHandler < BaseHandler
    def get
      return redirect("/") if elevated?
      page("admin/login.html", {"next" => safe_next(query("next")), "email" => ""})
    end

    def post
      result = Auth.login_password(field("email"), request.data.fetch("password", "").to_s, ip, user_agent, Config.now)
      if handle = result.pending
        request.cookies.set(PENDING_COOKIE, handle, expires: Time.utc + Config::PENDING_LIFETIME, http_only: true,
          secure: secure_cookies?, same_site: "Strict")
        return redirect("/login/second-factor?next=#{URI.encode_www_form(safe_next(field("next")))}")
      end
      if opened = result.opened
        open_session(opened)
        return redirect(elevated? ? safe_next(field("next")) : "/account")
      end
      error = I18n.t(result.error || "admin.errors.login.invalid", seconds: result.wait.try(&.total_seconds.ceil.to_i).to_s)
      page("admin/login.html", {"next" => safe_next(field("next")), "email" => field("email"), "error" => error}, status: 422)
    end
  end

  class SecondFactorHandler < BaseHandler
    def get
      return redirect("/login") if request.cookies[PENDING_COOKIE]?.nil?
      page("admin/second_factor.html", {"next" => safe_next(query("next"))})
    end

    def post
      result = Auth.login_second_factor(request.cookies[PENDING_COOKIE]?, field("code"), ip, user_agent, Config.now)
      if opened = result.opened
        request.cookies.delete(PENDING_COOKIE)
        open_session(opened)
        return redirect(elevated? ? safe_next(field("next")) : "/account")
      end
      if result.error == "admin.errors.login.expired"
        flash["warning"] = I18n.t("admin.errors.login.expired")
        return redirect("/login")
      end
      error = I18n.t(result.error || "admin.errors.login.invalid", seconds: result.wait.try(&.total_seconds.ceil.to_i).to_s)
      page("admin/second_factor.html", {"next" => safe_next(field("next")), "error" => error}, status: 422)
    end
  end

  # Options WebAuthn d'une connexion par passkey (credential découvrable).
  class PasskeyLoginOptionsHandler < BaseHandler
    def post
      options, _ = Auth::Passkeys.authentication_options
      json(options)
    end
  end

  class PasskeyLoginHandler < BaseHandler
    def post
      user = Auth::Passkeys.finish_authentication(field("challenge_id"), field("credential_id"),
        field("authenticator_data"), field("client_data_json"), field("signature"), now: Config.now)
      return json({"ok" => false, "error" => I18n.t("admin.errors.login.invalid")}.to_json) unless user.can_sign_in?
      Auth::Throttle.record_success(user)
      opened = Auth::Sessions.open(user, Auth::PASSKEY, "passkey", ip, user_agent, Config.now)
      Audit.log(user, "auth.login", target: user, detail: {"level" => Auth::PASSKEY.to_s, "method" => "passkey"}, ip: ip)
      open_session(opened)
      json({"ok" => true, "redirect" => safe_next(field("next"))}.to_json)
    rescue error : Auth::Passkeys::Error
      json({"ok" => false, "error" => I18n.t(error.key)}.to_json, status: 422)
    end
  end

  class LogoutHandler < BaseHandler
    def post
      if session = session_record
        Auth::Sessions.revoke(session)
        Audit.log(session.user, "auth.logout", target: session.user, ip: ip)
      end
      request.cookies.delete(COOKIE, same_site: "Strict")
      redirect("/login")
    end
  end

  # Invitation : ouvre une session d'enrôlement (niveau 0) ; l'utilisateur
  # enrôle ensuite ses moyens sur la page du compte.
  class InvitationHandler < BaseHandler
    def get
      user = Auth::Invitations.peek(params["token"].to_s, Config.now)
      return page("admin/invitation.html", {"invalid" => true}, status: 404) if user.nil?
      page("admin/invitation.html", {"invited" => user, "token" => params["token"].to_s})
    end

    def post
      user = Auth::Invitations.consume(params["token"].to_s, Config.now)
      return page("admin/invitation.html", {"invalid" => true}, status: 404) if user.nil? || !user.can_sign_in?
      Auth::Sessions.revoke_all(user)
      opened = Auth::Sessions.open(user, Auth::ENROLLMENT, "invitation", ip, user_agent, Config.now)
      Audit.log(user, "auth.invitation", target: user, ip: ip)
      open_session(opened)
      redirect("/account")
    end
  end

  class LanguageHandler < BaseHandler
    def post
      locale = field("locale")
      if Config::LOCALES.includes?(locale)
        request.cookies.set(LOCALE_COOKIE, locale, expires: Time.utc + 365.days, same_site: "Lax", secure: secure_cookies?)
        if current = user?
          current.locale = locale
          current.save!
        end
      end
      redirect(safe_next(field("next")))
    end
  end

  # Sécurité du compte (ADR-002 D6) : moyens enrôlés, ce qui manque pour le
  # niveau exigé, élévation par passkey.
  class AccountHandler < AccountScreenHandler
    def get
      current = user
      secret = current.totp_pending_secret
      page("admin/account.html", {
        "account"       => current,
        "level"         => level,
        "required"      => Auth.required_level(current),
        "missing"       => Auth.missing(current).map { |item| "admin.account.missing_items.#{item}" },
        "passkeys"      => Passkey.filter(user_id: current.pk).order("created_at").to_a,
        "recovery_left" => Auth::RecoveryCodes.remaining(current),
        # `nil` et non "" : une chaîne vide est vraie dans un gabarit Marten
        # (seuls nil, false et 0 sont faux) ; le bouton « activer » ne
        # s'affichait jamais.
        "totp_secret"      => secret,
        "totp_uri"         => secret ? Auth::Totp.provisioning_uri(current, secret) : nil,
        "enrollment"       => level == Auth::ENROLLMENT,
        "password_allowed" => !current.super_admin?,
      })
    end
  end

  # Choix du mot de passe (enrôlement, ou changement à niveau suffisant).
  class AccountPasswordHandler < AccountScreenHandler
    def post
      current = user
      raise Access::Denied.new("password") if current.super_admin?
      if current.usable_password? && level < Auth::TWO_FACTOR && level != Auth::ENROLLMENT
        raise Access::Denied.new("password")
      end
      password = request.data.fetch("password", "").to_s
      errors = Auth::Passwords.errors(password, current)
      errors << "admin.errors.password.mismatch" if password != request.data.fetch("confirmation", "").to_s
      unless errors.empty?
        flash["danger"] = errors.map { |key| I18n.t(key) }.join(" ")
        return redirect("/account")
      end
      current.password_digest = Auth::Passwords.hash(password)
      current.password_changed_at = Config.now
      current.save!
      Audit.log(current, "account.password", target: current, ip: ip)
      flash["success"] = I18n.t("admin.account.password_saved")
      redirect("/account")
    end
  end

  class AccountTotpHandler < AccountScreenHandler
    def post
      current = user
      raise Access::Denied.new("totp") if current.super_admin?
      if field("command") == "begin"
        Auth::Totp.begin(current)
        return redirect("/account#totp")
      end
      if Auth::Totp.confirm(current, field("code").gsub(/\s/, ""), Config.now)
        codes = Auth::RecoveryCodes.ensure(current)
        # Mot de passe (s'il est choisi) + TOTP confirmé : niveau 2.
        if (session = session_record) && current.usable_password?
          Auth::Sessions.raise_level(session, Auth::TWO_FACTOR, "totp")
        end
        Audit.log(current, "account.totp", target: current, ip: ip)
        return page("admin/recovery_codes.html", {"codes" => codes}) unless codes.empty?
        flash["success"] = I18n.t("admin.account.totp_enabled")
      else
        flash["danger"] = I18n.t("admin.errors.login.code")
      end
      redirect("/account")
    end
  end

  class RecoveryCodesHandler < AccountScreenHandler
    def post
      raise Access::Denied.new("recovery") unless elevated?
      codes = Auth::RecoveryCodes.generate(user)
      Audit.log(user, "account.recovery_codes", target: user, ip: ip)
      page("admin/recovery_codes.html", {"codes" => codes})
    end
  end

  class PasskeyRegisterOptionsHandler < AccountScreenHandler
    def post
      options, _ = Auth::Passkeys.registration_options(user)
      json(options)
    end
  end

  class PasskeyRegisterHandler < AccountScreenHandler
    def post
      current = user
      Auth::Passkeys.finish_registration(current, field("challenge_id"), field("attestation_object"),
        field("client_data_json"), field("name"))
      codes = Auth::RecoveryCodes.ensure(current)
      Audit.log(current, "account.passkey", target: current, ip: ip)
      flash["success"] = I18n.t("admin.account.passkey_added")
      return json({"ok" => true, "redirect" => "/account"}.to_json) if codes.empty?
      # Premiers codes de récupération : montrés tout de suite, une seule
      # fois (ils n'existent qu'à cet instant en clair), comme après
      # l'activation du TOTP. `passkey.js` remplace le contenu de la page.
      html = Marten.templates.get_template("admin/_recovery_codes.html").render({"codes" => codes})
      json({"ok" => true, "html" => html}.to_json)
    rescue error : Auth::Passkeys::Error
      json({"ok" => false, "error" => I18n.t(error.key)}.to_json, status: 422)
    end
  end

  # Élévation par passkey de la session courante (niveau 3).
  class ElevateOptionsHandler < AccountScreenHandler
    def post
      options, _ = Auth::Passkeys.authentication_options(user)
      json(options)
    end
  end

  class ElevateHandler < AccountScreenHandler
    def post
      Auth::Passkeys.finish_authentication(field("challenge_id"), field("credential_id"), field("authenticator_data"),
        field("client_data_json"), field("signature"), expected_user: user, now: Config.now)
      # Élévation et ré-authentification forte : l'heure est retenue pour
      # les opérations confirmées par une seule personne (D-VAL2-004).
      if session = session_record
        Auth::Sessions.mark_strong(session, Auth::PASSKEY, "passkey", Config.now)
      end
      Audit.log(user, "auth.elevate", target: user, ip: ip)
      json({"ok" => true, "redirect" => safe_next(field("next"), "/")}.to_json)
    rescue error : Auth::Passkeys::Error
      json({"ok" => false, "error" => I18n.t(error.key)}.to_json, status: 422)
    end
  end
end
