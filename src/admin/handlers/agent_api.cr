# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # API de l'exécutant (ADR-008 D4), `/api/agent/v1/…` : l'exécutant tire,
  # l'admin n'ouvre aucune connexion vers les serveurs. Authentification par
  # le jeton du serveur (`Authorization: Bearer …`), JSON en entrée et en
  # sortie. Un exécutant ne voit que les tâches de son serveur.
  abstract class AgentApiHandler < Marten::Handlers::Base
    # Pas de jeton CSRF : aucun cookie, le jeton du serveur authentifie.
    # Réglage répété dans chaque handler (variable de classe non héritée).
    macro inherited
      protect_from_forgery false
    end

    @server : Server?

    before_dispatch :authenticate

    def server : Server
      @server || raise Access::Denied.new("serveur")
    end

    def body : JSON::Any
      raw = request.body
      raw.empty? ? JSON::Any.new({} of String => JSON::Any) : JSON.parse(raw)
    rescue JSON::ParseException
      JSON::Any.new({} of String => JSON::Any)
    end

    def task_of_server : Task?
      Task.filter(id: params["id"].to_s.to_i64, server_id: server.pk).first
    end

    def error(status : Int32, code : String)
      json({"ok" => false, "error" => code}.to_json, status: status)
    end

    private def authenticate
      header = request.headers["Authorization"]? || ""
      token = header.starts_with?("Bearer ") ? header[7..].strip : nil
      @server = Directory.server_for_token(token)
      return error(401, "unauthorized") if @server.nil?
      server = self.server
      server.last_seen_at = Config.now
      server.agent_version = request.headers["X-Partiduo-Agent"]?.try(&.[0, 32]?) || server.agent_version
      server.agent_mode = request.headers["X-Partiduo-Agent-Mode"]?.try(&.[0, 16]?) || server.agent_mode
      server.save!
      nil
    end
  end

  # Réclame la prochaine tâche (ou reprend une tâche au bail expiré).
  class AgentClaimHandler < AgentApiHandler
    def post
      task = Tasks.claim(server, Config.now)
      return json({"ok" => true, "task" => nil, "api" => Protocol::API_VERSION}.to_json) if task.nil?
      json({
        "ok"   => true,
        "api"  => Protocol::API_VERSION,
        "task" => {
          "id"           => task.pk,
          "kind"         => task.kind,
          "attempt"      => task.attempts,
          "dossier"      => task.dossier_slug,
          "params"       => task.params_json,
          "requested_by" => task.requested_by_label,
          "lease_until"  => task.lease_until.try(&.to_rfc3339),
        },
      }.to_json)
    end
  end

  # Journal intermédiaire ; prolonge le bail.
  class AgentLogHandler < AgentApiHandler
    def post
      task = task_of_server
      return error(404, "not_found") if task.nil?
      return error(409, "not_running") unless task.state == "running"
      lines = body["lines"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
      Tasks.report(task, lines.first(1000), Config.now)
      json({"ok" => true, "lease_until" => task.lease_until.try(&.to_rfc3339)}.to_json)
    end
  end

  # Fin de tâche : réussite ou échec, résultat, erreur, dernières lignes.
  # Idempotent : une tâche déjà terminée répond `ok` sans rien changer
  # (l'exécutant peut rejouer son compte rendu après une coupure).
  class AgentFinishHandler < AgentApiHandler
    def post
      task = task_of_server
      return error(404, "not_found") if task.nil?
      return json({"ok" => true, "state" => task.state}.to_json) if task.finished
      return error(409, "not_running") unless task.state == "running"
      data = body
      ok = data["ok"]?.try(&.as_bool?) || false
      result = data["result"]? || JSON::Any.new({} of String => JSON::Any)
      lines = data["lines"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
      Tasks.finish(task, ok, result, data["error"]?.try(&.as_s?) || "", lines.first(1000), Config.now)
      json({"ok" => true, "state" => task.state}.to_json)
    end
  end
end
