# SPDX-License-Identifier: AGPL-3.0-or-later

require "http/server"
require "json"

module AdminSpec
  # Administration simulée pour les specs de l'exécutant : l'API
  # `/api/agent/v1/…` servie sur 127.0.0.1, une file en mémoire.
  class FakeAdmin
    TOKEN = "jeton-du-serveur"

    getter queue = [] of Hash(String, JSON::Any)
    getter logs = Hash(Int64, Array(String)).new { |hash, key| hash[key] = [] of String }
    getter finished = {} of Int64 => JSON::Any
    getter claims = 0
    getter headers = [] of HTTP::Headers
    getter url : String

    def initialize
      @server = HTTP::Server.new { |context| handle(context) }
      address = @server.bind_tcp("127.0.0.1", 0)
      @url = "http://127.0.0.1:#{address.port}"
      spawn { @server.listen }
      Fiber.yield
    end

    def close : Nil
      @server.close
    end

    def push(id : Int64, kind : String, params : Hash, attempt : Int32 = 1) : Nil
      queue << {"id" => JSON::Any.new(id), "kind" => JSON::Any.new(kind), "attempt" => JSON::Any.new(attempt.to_i64),
                "dossier" => JSON::Any.new(params["slug"]?.to_s), "params" => JSON.parse(params.to_json),
                "requested_by" => JSON::Any.new("spec@example.com")}
    end

    def config(mode = PartiduoAgent::Mode::DryRun) : PartiduoAgent::Config
      config = PartiduoAgent::Config.new
      config.admin_url = url
      config.token = TOKEN
      config.mode = mode
      config.state_dir = File.join(Dir.tempdir, "partiduo-agent-spec-#{Random::Secure.hex(4)}")
      config.backup_dir = File.join(config.state_dir, "backups")
      config.work_dir = File.join(config.state_dir, "work")
      config.once = true
      config
    end

    private def handle(context : HTTP::Server::Context) : Nil
      headers << context.request.headers
      if context.request.headers["Authorization"]? != "Bearer #{TOKEN}"
        context.response.status_code = 401
        context.response.print(%({"ok":false,"error":"unauthorized"}))
        return
      end
      body = JSON.parse(context.request.body.try(&.gets_to_end).presence || "{}")
      context.response.content_type = "application/json"
      case context.request.path
      when "/api/agent/v1/claim"
        @claims += 1
        task = queue.shift?
        context.response.print({"ok" => true, "task" => task}.to_json)
      when %r{/tasks/(\d+)/log\z}
        logs[$1.to_i64].concat(body["lines"].as_a.map(&.as_s))
        context.response.print(%({"ok":true}))
      when %r{/tasks/(\d+)/finish\z}
        id = $1.to_i64
        logs[id].concat(body["lines"].as_a.map(&.as_s))
        finished[id] = body
        context.response.print(%({"ok":true}))
      else
        context.response.status_code = 404
      end
    end
  end
end
