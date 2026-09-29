# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # File de tâches (ADR-008 D4). L'application web n'a aucun privilège
  # système : elle enregistre des tâches, que l'exécutant de chaque serveur
  # tire, exécute et rend.
  module Tasks
    alias Params = Hash(String, JSON::Any)

    # Taille maximale du journal conservé par tâche (les lignes les plus
    # anciennes sont gardées : elles disent ce qui a été fait).
    LOG_LIMIT = 200_000

    def self.any(value) : JSON::Any
      JSON.parse(value.to_json)
    end

    # Enregistre une tâche. Idempotence côté admin : une tâche identique
    # (même type, même dossier, mêmes paramètres) encore en attente ou en
    # cours est rendue au lieu d'en créer une seconde.
    def self.enqueue(kind : String, server : Server, params : Params, requested_by : User? = nil,
                     dossier : Dossier? = nil, wave : Wave? = nil, wave_rank : Int32? = nil,
                     requested_by_label : String? = nil, data_keys : Array(String)? = nil) : Task
      raise ArgumentError.new("type de tâche inconnu : #{kind}") unless Protocol.valid_kind?(kind)
      serialized = params.to_json
      secrets = data_keys ? data_keys.to_json : ""
      existing = Task.filter(kind: kind, server_id: server.pk, state__in: %w[pending running], params: serialized)
      existing = dossier ? existing.filter(dossier_id: dossier.pk) : existing.filter(dossier_id__isnull: true)
      if task = existing.first
        # Même demande encore en attente : la clé de données fournie de
        # nouveau lui est remise.
        if data_keys && task.state == "pending"
          task.data_keys = secrets
          task.save!
        end
        return task
      end
      task = Task.create!(kind: kind, server: server, dossier: dossier, params: serialized,
        requested_by_id: requested_by.try(&.pk), requested_by_label: requested_by_label || requested_by.try(&.email.to_s) || "system",
        wave: wave, wave_rank: wave_rank, data_keys: secrets)
      Audit.log(requested_by, "task.enqueue", target: task,
        detail: {"kind" => kind, "dossier" => dossier.try(&.slug).to_s}, actor_label: requested_by ? nil : "system")
      task
    end

    # Paramètres communs à toute tâche portant sur un dossier.
    def self.dossier_params(dossier : Dossier) : Params
      {
        "slug"       => any(dossier.slug),
        "host"       => any(dossier.host),
        "domain"     => any(dossier.server.try(&.domain) || Config.domain),
        "database"   => any(dossier.database),
        "modules"    => any(dossier.module_list),
        "extensions" => any(dossier.extension_list),
        "version"    => any(dossier.version),
        # Langue du courriel d'invitation quand le serveur le remet lui-même
        # (D-CRA-003).
        "locale" => any(dossier.locale.to_s),
      }
    end

    # Réclamation par l'exécutant d'un serveur : sa plus ancienne tâche en
    # attente, ou une tâche en cours dont le bail a expiré (coupure : la
    # tâche est reprise, ADR-008 D4). `FOR UPDATE SKIP LOCKED` : deux
    # exécutants ne prennent jamais la même tâche.
    CLAIM_SQL = <<-SQL
      UPDATE admin_task
         SET state = 'running', attempts = attempts + 1, claimed_at = $2, lease_until = $3,
             started_at = COALESCE(started_at, $2), updated_at = $2
       WHERE id = (
         SELECT id FROM admin_task
          WHERE server_id = $1
            AND (state = 'pending' OR (state = 'running' AND lease_until < $2))
          ORDER BY id
          FOR UPDATE SKIP LOCKED
          LIMIT 1)
      RETURNING id
      SQL

    def self.claim(server : Server, now : Time = Config.now) : Task?
      lease = now + Protocol::LEASE_SECONDS.seconds
      id = Marten::DB::Connection.default.open do |db|
        db.query_one?(CLAIM_SQL, server.pk!.as(Int64), now, lease, as: Int64)
      end
      id ? Task.get!(id: id) : nil
    end

    # Clés de données d'une tâche, rendues une seule fois puis effacées
    # (D-CHF-005) : l'exécutant qui la reprend après une coupure ne les
    # reçoit plus, la restauration est à redemander avec la clé.
    TAKE_SECRETS_SQL = <<-SQL
      UPDATE admin_task t SET data_keys = ''
        FROM (SELECT id, data_keys FROM admin_task WHERE id = $1 FOR UPDATE) previous
       WHERE t.id = previous.id
      RETURNING previous.data_keys
      SQL

    def self.take_secrets(task : Task) : Array(String)
      raw = Marten::DB::Connection.default.open do |db|
        db.query_one?(TAKE_SECRETS_SQL, task.pk!.as(Int64), as: String)
      end
      task.data_keys = ""
      return [] of String if raw.nil? || raw.empty?
      Array(String).from_json(raw)
    rescue JSON::ParseException
      [] of String
    end

    # Compte rendu intermédiaire : lignes de journal, bail prolongé.
    def self.report(task : Task, lines : Array(String), now : Time = Config.now) : Nil
      append_log(task, lines)
      task.lease_until = now + Protocol::LEASE_SECONDS.seconds if task.state == "running"
      task.save!
    end

    # Fin de tâche : état, résultat, erreur, puis effets sur l'inventaire,
    # dans une transaction. Le passage `running` → état final est une mise
    # à jour conditionnelle : seul le premier de deux comptes rendus
    # concurrents applique les effets (sauvegardes, courriels). Rend `true`
    # si ce compte rendu a été appliqué. Un envoi d'invitation en échec
    # annule tout et lève `Effects::DeliveryError`, après avoir ouvert une
    # alerte : la tâche reste en cours, l'exécutant rendra compte de
    # nouveau (D-AFN-008).
    def self.finish(task : Task, ok : Bool, result : JSON::Any, error : String = "",
                    lines = [] of String, now : Time = Config.now) : Bool
      return false if task.finished
      state = ok ? "succeeded" : "failed"
      applied = false
      begin
        Marten::DB::Connection.default.transaction do
          claimed = Task.filter(id: task.pk, state: "running")
            .update(state: state, finished_at: now, lease_until: nil, updated_at: now)
          if claimed == 1
            task.data_keys = ""
            append_log(task, lines)
            task.state = state
            task.finished_at = now
            task.lease_until = nil
            task.result = Effects.sanitize(task, result).to_json
            task.error = error[0, 4000]? || ""
            task.save!
            Audit.log(nil, "task.#{task.state}", target: task,
              detail: {"kind" => task.kind.to_s, "dossier" => task.dossier_slug, "error" => task.error.to_s},
              outcome: ok ? "ok" : "fail", actor_label: "agent:#{task.server.try(&.name)}")
            Effects.apply(task, ok, result, now)
            applied = true
          end
        end
      rescue ex : Effects::DeliveryError
        task.reload
        Alerts.open("mail_failed", "danger", dossier: task.dossier, detail: "task #{task.pk} #{ex.message}", now: now)
        raise ex
      end
      task.reload unless applied
      applied
    end

    # Types soumis à double validation : jamais rejoués sans une nouvelle
    # validation (l'état du dossier a pu changer, D-AFN-010).
    DOUBLE_VALIDATION = %w[instance.admin_invite instance.delete]

    # Une tâche qui a reçu une clé de données du cabinet ne se rejoue pas :
    # la clé n'est plus nulle part, elle est à fournir de nouveau (D-CHF-005).
    def self.retryable?(task : Task) : Bool
      task.state == "failed" && !DOUBLE_VALIDATION.includes?(task.kind) &&
        task.params_json["key_provided"]?.try(&.as_bool?) != true
    end

    # Rejouer une tâche échouée : même type, mêmes paramètres ; les étapes
    # déjà faites sont sautées par l'exécutant (tâches idempotentes).
    def self.retry(user : User, task : Task) : Bool
      return false unless retryable?(task)
      task.state = "pending"
      task.finished_at = nil
      task.error = ""
      task.save!
      if dossier = task.dossier
        dossier.state = "active" if dossier.state == "error" && task.kind != "instance.create"
        dossier.save!
      end
      Audit.log(user, "task.retry", target: task)
      true
    end

    def self.cancel(user : User, task : Task) : Bool
      return false unless task.state == "pending"
      task.state = "cancelled"
      task.data_keys = ""
      task.finished_at = Config.now
      task.save!
      Audit.log(user, "task.cancel", target: task)
      true
    end

    private def self.append_log(task : Task, lines : Array(String)) : Nil
      return if lines.empty?
      log = task.log.to_s + lines.map { |line| line.gsub(/[\r\n]+/, " ") + "\n" }.join
      task.log = log.size > LOG_LIMIT ? log[0, LOG_LIMIT] : log
    end
  end
end
