# SPDX-License-Identifier: AGPL-3.0-or-later

require "http/client"
require "json"

module PartiduoAgent
  # Tâche reçue de l'administration.
  # `data_keys` : clés de données remises une seule fois pour lire une
  # sauvegarde chiffrée par la clé du cabinet (D-CHF-005), jamais dans les
  # paramètres.
  record TaskInfo, id : Int64, kind : String, attempt : Int32, dossier : String, params : JSON::Any,
    requested_by : String, data_keys : Array(String) = [] of String

  class ApiError < Exception
  end

  # Client de l'API de l'exécutant (`/api/agent/v1/…`) : l'exécutant tire,
  # l'admin n'ouvre aucune connexion vers le serveur (ADR-008 D4).
  class Client
    def initialize(@config : Config)
      @base = URI.parse(@config.admin_url)
    end

    def claim : TaskInfo?
      data = post("/api/agent/v1/claim", {} of String => String)
      task = data["task"]?
      return if task.nil? || task.raw.nil?
      TaskInfo.new(task["id"].as_i64, task["kind"].as_s, task["attempt"]?.try(&.as_i?) || 1,
        task["dossier"]?.try(&.as_s?) || "", task["params"], task["requested_by"]?.try(&.as_s?) || "",
        task["secrets"]?.try(&.["data_keys"]?).try(&.as_a?).try(&.compact_map(&.as_s?)) || [] of String)
    end

    def log(task_id : Int64, lines : Array(String)) : Nil
      return if lines.empty?
      post("/api/agent/v1/tasks/#{task_id}/log", {"lines" => lines})
    end

    def finish(task_id : Int64, ok : Bool, result : JSON::Any, error : String, lines : Array(String)) : Nil
      post("/api/agent/v1/tasks/#{task_id}/finish", {"ok" => ok, "result" => result, "error" => error, "lines" => lines})
    end

    private def post(path : String, payload) : JSON::Any
      headers = HTTP::Headers{
        "Authorization"         => "Bearer #{@config.token}",
        "Content-Type"          => "application/json",
        "Accept"                => "application/json",
        "X-Partiduo-Agent"      => VERSION,
        "X-Partiduo-Agent-Mode" => @config.mode.label,
      }
      client = HTTP::Client.new(@base)
      client.connect_timeout = 10.seconds
      client.read_timeout = 60.seconds
      prefix = @base.path.rstrip('/')
      response = client.post("#{prefix}#{path}", headers: headers, body: payload.to_json)
      unless response.success?
        raise ApiError.new("#{path} : HTTP #{response.status_code} #{response.body[0, 200]?}")
      end
      JSON.parse(response.body)
    rescue ex : IO::Error | Socket::Error
      raise ApiError.new("#{path} : #{ex.message}")
    ensure
      client.try(&.close)
    end
  end
end
