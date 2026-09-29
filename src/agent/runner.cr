# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAgent
  # Boucle de l'exécutant : réclame une tâche, l'exécute étape par étape en
  # renvoyant son journal, rend compte ; recommence.
  class Runner
    getter config : Config
    getter client : Client
    # Dernier système construit (à blanc : les specs y lisent l'état simulé).
    getter last_system : System?

    # Système partagé entre les tâches (mode à blanc : l'état simulé
    # persiste d'une tâche à l'autre, comme un vrai serveur).
    @dry : DrySystem?

    def initialize(@config : Config, @client : Client = Client.new(config))
    end

    def build_system(sink : Proc(String, Nil)) : System
      case config.mode
      in Mode::DryRun
        dry = (@dry ||= DrySystem.new(config, sink))
        dry.sink = sink
        dry
      in Mode::Local      then LocalSystem.new(config, sink)
      in Mode::Production then ProductionSystem.new(config, sink)
      end
    end

    # Traite au plus une tâche ; `false` s'il n'y en avait pas.
    def run_once : Bool
      task = client.claim
      return false if task.nil?
      execute(task)
      true
    end

    def run : Nil
      Log.info { "partiduo-agent #{VERSION} (#{config.mode.label}) → #{config.admin_url}" }
      loop do
        processed = run_once
        break if config.once
        sleep config.poll_interval unless processed
      rescue ex : ApiError
        Log.warn { ex.message }
        break if config.once
        sleep config.poll_interval
      end
    end

    def execute(task : TaskInfo) : Nil
      pending = [] of String
      sink = ->(line : String) { pending << "#{Time.utc.to_s("%H:%M:%S")} #{line}"; nil }
      system = build_system(sink)
      @last_system = system
      journal = Journal.new(File.join(config.state_dir, "tasks"), task.id)
      ctx = Context.new(task, system, journal)
      ctx.on_step = ->(_step : String) do
        # Compte rendu après chaque étape : journal et bail prolongé.
        begin
          client.log(task.id, pending.dup)
          pending.clear
        rescue ex : ApiError
          Log.warn { "journal non transmis : #{ex.message}" }
        end
        nil
      end
      sink.call("tâche #{task.id} #{task.kind} (#{task.dossier.presence || "parc"}), essai #{task.attempt}, mode #{config.mode.label}")
      unless PartiduoAdmin::Protocol.valid_kind?(task.kind)
        client.finish(task.id, false, JSON::Any.new({} of String => JSON::Any), "type de tâche refusé : #{task.kind}", pending)
        return
      end
      begin
        Plans.run(ctx)
        client.finish(task.id, true, JSON.parse(ctx.result.to_json), "", pending)
        journal.clear
      rescue error : ApiError
        # Compte rendu non transmis : la tâche reprendra ; ses clés de
        # données ne restent pas sur le disque pour autant (D-CHF-006).
        journal.forget_secrets
        raise error
      rescue error : StepError
        sink.call("échec : #{error.message}")
        # Journal de reprise conservé : une nouvelle tentative saute les
        # étapes faites.
        journal.forget_secrets
        client.finish(task.id, false, JSON.parse(ctx.result.to_json), error.message.to_s, pending)
      rescue error
        journal.forget_secrets
        sink.call("erreur inattendue : #{error.class} #{error.message}")
        client.finish(task.id, false, JSON.parse(ctx.result.to_json), "#{error.class} : #{error.message}", pending)
      end
    end
  end
end
