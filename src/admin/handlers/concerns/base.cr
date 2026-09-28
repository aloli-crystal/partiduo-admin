# SPDX-License-Identifier: AGPL-3.0-or-later

class Marten::HTTP::Request
  # Session d'administration de la requête, résolue une seule fois.
  property admin_session : PartiduoAdmin::Session? = nil
  property admin_session_resolved : Bool = false
end

module PartiduoAdmin
  # Champ de formulaire présenté par `admin/_field.html` : étiquette reliée,
  # aide et erreurs annoncées (`aria-describedby`, `aria-invalid`).
  class FormField
    include Marten::Template::Object::Auto

    record Option, value : String, label : String, selected : Bool = false do
      include Marten::Template::Object::Auto
    end

    getter name : String
    getter label : String
    getter value : String
    getter type : String
    getter options : Array(Option)
    getter errors : Array(String)
    getter required : Bool
    # Aide : `nil` si vide (une chaîne vide est vraie dans un gabarit de
    # Marten : `{% if field.help %}` produisait un paragraphe vide et un
    # `aria-describedby` vers lui).
    @help : String

    def help : String?
      @help.presence
    end

    getter checked : Bool

    def initialize(@name, @label, @value = "", @type = "text", @options = [] of Option, @errors = [] of String,
                   @required = false, @help = "", @checked = false)
    end

    def id : String
      "f-#{name.tr("_", "-")}"
    end

    def error_id : String
      "#{id}-error"
    end

    def help_id : String
      "#{id}-help"
    end

    def describedby : String?
      ids = [] of String
      ids << help_id if help
      ids << error_id unless errors.empty?
      ids.join(' ').presence
    end

    def has_errors : Bool
      !errors.empty?
    end
  end

  # Drapeaux pour un gabarit (`{% if can.archive %}`) : un objet plutôt
  # qu'un dictionnaire, que les gabarits de Marten lisent mal au-delà de
  # huit entrées (partiduo-app, B-UI-004).
  class Flags
    include Marten::Template::Object::Auto

    def initialize(@flags : Hash(String, Bool))
    end

    def [](key : String) : Bool
      @flags.fetch(key) { raise KeyError.new(key) }
    end
  end

  # Base des handlers : session, utilisateur, langue, lecture des
  # formulaires, traduction des erreurs.
  abstract class BaseHandler < Marten::Handlers::Base
    COOKIE         = "partiduo_admin_session"
    PENDING_COOKIE = "partiduo_admin_pending"
    LOCALE_COOKIE  = "partiduo_admin_locale"

    before_dispatch :activate_locale

    rescue_from Access::Denied do
      error_page(403)
    end

    def session_record : Session?
      unless request.admin_session_resolved
        request.admin_session = Auth::Sessions.find(request.cookies[COOKIE]?.presence, Config.now)
        request.admin_session_resolved = true
      end
      request.admin_session
    end

    def user? : User?
      session_record.try(&.user)
    end

    def user : User
      user? || raise Access::Denied.new("session")
    end

    def level : Int32
      (session_record.try(&.level) || 0).to_i32
    end

    def elevated? : Bool
      if current = user?
        level >= Auth.required_level(current)
      else
        false
      end
    end

    def field(name : String) : String
      (request.data.fetch(name, nil).try(&.to_s) || "").strip
    end

    def fields(name : String) : Array(String)
      values = request.data.fetch_all(name, nil)
      return [] of String if values.nil?
      values.map(&.to_s.strip).reject(&.empty?)
    end

    def query(name : String) : String
      request.query_params.fetch(name, nil).try(&.to_s) || ""
    end

    def id_param(name : String = "id") : Int64
      params[name].to_s.to_i64
    end

    def ip : String
      if Marten.settings.use_x_forwarded_proto?
        request.headers["X-Real-IP"]?.presence || request.host.to_s
      else
        request.headers["X-Real-IP"]?.presence || ""
      end
    end

    def user_agent : String
      request.headers["User-Agent"]? || ""
    end

    def htmx? : Bool
      request.headers["HX-Request"]? == "true"
    end

    # Redirection compatible HTMX (`HX-Redirect`).
    def go(url : String) : Marten::HTTP::Response
      if htmx?
        response = Marten::HTTP::Response.new(content: "", status: 204)
        response.headers["HX-Redirect"] = url
        response
      else
        redirect(url)
      end
    end

    # Messages d'erreur d'un champ (liste vide s'il n'y en a pas).
    def errs(translated : Hash(String, Array(String)), name : String) : Array(String)
      translated[name]? || [] of String
    end

    def translate(errors : Fleet::Errors) : Hash(String, Array(String))
      errors.transform_values { |keys| keys.map { |key| I18n.t(key) } }
    end

    def page(template : String, values = {} of String => String, status : Int32 = 200) : Marten::HTTP::Response
      context["current_user"] = user?
      context["elevated"] = elevated?
      context["locale"] = I18n.locale
      context["locales"] = Config::LOCALES
      context["current_path"] = request.full_path
      if current = user?
        context["nav_fleet"] = Access.fleet?(current)
        context["nav_admin"] = !current.file_manager?
        context["open_alerts"] = Alerts.visible(current).count
        context["pending_approvals"] = Approvals.visible(current).filter(state: "pending").count
      end
      render(template, listed(values), status: status)
    end

    # Pour les gabarits de Marten, une liste vide est vraie dans un
    # `{% if %}` : les listes vides passent comme `nil`.
    private def listed(values : Hash)
      values.transform_values { |value| value.is_a?(Array) && value.empty? ? nil : value }
    end

    def error_page(status : Int32) : Marten::HTTP::Response
      page("admin/error.html", {"status" => status, "title_key" => "admin.errors.http.#{status}"}, status: status)
    end

    def open_session(opened : Auth::Sessions::Opened) : Nil
      # Cookie de session du navigateur : l'échéance est tenue côté serveur.
      request.cookies.set(COOKIE, opened.token, http_only: true, secure: secure_cookies?, same_site: "Strict")
      request.admin_session = opened.session
      request.admin_session_resolved = true
    end

    def secure_cookies? : Bool
      request.secure? || Marten.env.production?
    end

    # Adresse de retour sûre : un chemin local seulement.
    def safe_next(value : String, default : String = "/") : String
      value.starts_with?('/') && !value.starts_with?("//") && !value.includes?('\\') ? value : default
    end

    private def activate_locale
      locale = user?.try(&.locale) || request.cookies[LOCALE_COOKIE]?
      I18n.activate(locale) if locale && Config::LOCALES.includes?(locale)
      nil
    end
  end

  # Écran derrière la connexion, au niveau exigé par le rôle (ADR-008 D2).
  abstract class ScreenHandler < BaseHandler
    before_dispatch :require_elevated

    private def require_elevated
      return redirect("/login?next=#{URI.encode_www_form(request.full_path)}") if user?.nil?
      unless elevated?
        flash["warning"] = I18n.t("admin.account.elevation_needed")
        return redirect("/account")
      end
      nil
    end

    def dossier! : Dossier
      dossier = Dossier.filter(id: id_param).first
      raise Access::Denied.new("dossier") if dossier.nil? || !Access.in_scope?(user, dossier)
      dossier
    end

    def require_fleet! : Nil
      raise Access::Denied.new("fleet") unless Access.fleet?(user)
    end

    def require_admin! : Nil
      raise Access::Denied.new("admin") if user.file_manager?
    end
  end

  # Pages du compte : ouvertes à toute session, même d'enrôlement ou sous le
  # niveau exigé, pour qu'elle s'élève.
  abstract class AccountScreenHandler < BaseHandler
    before_dispatch :require_session

    private def require_session
      return redirect("/login") if user?.nil?
      nil
    end
  end
end
