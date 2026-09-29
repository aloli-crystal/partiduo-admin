# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Serveur d'hébergement (ADR-008 D4) : son exécutant s'authentifie par un
  # jeton propre, conservé en empreinte. Un seul au départ ; le modèle en
  # accepte plusieurs.
  class Server < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :name, :string, max_size: 64, unique: true
    field :hostname, :string, max_size: 255
    field :domain, :string, max_size: 255
    field :token_digest, :string, max_size: 64, unique: true
    field :active, :bool, default: true
    field :agent_version, :string, max_size: 32, blank: true, default: ""
    field :agent_mode, :string, max_size: 16, blank: true, default: ""
    field :last_seen_at, :date_time, null: true, blank: true
    field :disk_total_bytes, :big_int, null: true, blank: true
    field :disk_free_bytes, :big_int, null: true, blank: true
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def disk_free_ratio : Float64?
      total = disk_total_bytes
      free = disk_free_bytes
      return if total.nil? || free.nil? || total <= 0
      free / total
    end

    def disk_free_percent : String
      disk_free_ratio.try { |ratio| "#{(ratio * 100).round.to_i} %" } || "—"
    end
  end

  # Version publiée de partiduo-app, déployable sur le parc.
  class Release < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :version, :string, max_size: 32, unique: true
    field :notes, :text, blank: true, default: ""
    field :is_default, :bool, default: false
    field :created_at, :date_time, auto_now_add: true
  end

  # Dossier (inventaire, ADR-001 D2) : une instance, sa base, son URL. Aucune
  # donnée comptable (ADR-008 D3) : `label` est la raison sociale transmise au
  # provisionnement, rien de plus.
  class Dossier < Marten::Model
    STATES    = %w[creating active suspended archived deleted error]
    SCHEDULES = %w[daily weekly none]

    field :id, :big_int, primary_key: true, auto: true
    field :slug, :string, max_size: 40, unique: true
    field :label, :string, max_size: 150
    field :regime, :string, max_size: 2
    field :locale, :string, max_size: 8, default: "fr"
    field :siren, :string, max_size: 9, blank: true, default: ""
    field :vat_number, :string, max_size: 20, blank: true, default: ""
    field :modules, :string, max_size: 255, default: ""
    field :extensions, :string, max_size: 255, blank: true, default: ""
    field :admin_email, :string, max_size: 254
    field :server, :many_to_one, to: PartiduoAdmin::Server, on_delete: :protect
    field :firm, :many_to_one, to: PartiduoAdmin::Firm, on_delete: :protect
    field :payer, :many_to_one, to: PartiduoAdmin::Payer, on_delete: :protect
    field :version, :string, max_size: 32, blank: true, default: ""
    field :database, :string, max_size: 63, blank: true, default: ""
    field :state, :string, max_size: 16, default: "creating"
    field :backup_schedule, :string, max_size: 8, default: "daily"
    field :backup_retention_days, :int, default: 30
    field :test_restore_days, :int, default: 30
    # Chiffrement des sauvegardes : vide, celui du cabinet (D-CHF-001).
    field :backup_encryption, :string, max_size: 16, blank: true, default: ""
    field :service_state, :string, max_size: 16, blank: true, default: ""
    field :database_state, :string, max_size: 16, blank: true, default: ""
    field :cert_expires_at, :date_time, null: true, blank: true
    field :health_checked_at, :date_time, null: true, blank: true
    field :suspended_at, :date_time, null: true, blank: true
    field :archived_at, :date_time, null: true, blank: true
    field :retention_until, :date_time, null: true, blank: true
    field :deleted_at, :date_time, null: true, blank: true
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def host : String
      "#{slug}.#{server.try(&.domain) || Config.domain}"
    end

    def module_list : Array(String)
      modules.to_s.split(',').map(&.strip).reject(&.empty?)
    end

    def extension_list : Array(String)
      extensions.to_s.split(',').map(&.strip).reject(&.empty?)
    end

    def state_key : String
      "admin.dossiers.states.#{state}"
    end

    def schedule_key : String
      "admin.schedules.#{backup_schedule}"
    end

    # Chiffrement effectif des prochaines sauvegardes : celui du dossier,
    # sinon celui du cabinet.
    def effective_encryption : String
      backup_encryption.presence || firm.try(&.backup_encryption) || "server"
    end

    def effective_encryption_key : String
      "admin.encryption.modes.#{effective_encryption}"
    end

    def encryption_inherited : Bool
      backup_encryption.to_s.empty?
    end

    # États relevés par la supervision (`running`, `stopped`, `ok`,
    # `unavailable`, `error`), traduits ; `nil` si jamais relevés.
    def service_state_key : String?
      health_key(service_state.to_s)
    end

    def database_state_key : String?
      health_key(database_state.to_s)
    end

    private def health_key(value : String) : String?
      return if value.empty?
      %w[running stopped ok unavailable error].includes?(value) ? "admin.health.states.#{value}" : "admin.health.states.unknown"
    end

    def firm_name : String
      firm.try(&.name) || ""
    end

    def payer_name : String
      payer.try(&.name) || ""
    end

    def server_name : String
      server.try(&.name) || ""
    end

    def last_backup : Backup?
      Backup.filter(dossier_id: pk, state__in: %w[done verified]).order("-taken_at").first
    end

    def last_backup_at : Time?
      last_backup.try(&.taken_at)
    end
  end

  # Gestionnaire de dossiers ↔ dossier confié (ADR-008 D2).
  class Assignment < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :user, :many_to_one, to: PartiduoAdmin::User, on_delete: :cascade
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, on_delete: :cascade
    field :created_at, :date_time, auto_now_add: true

    db_unique_constraint :admin_assignment_unique, field_names: [:user, :dossier]
  end

  # Montée de version par vagues (ADR-008 D5) : `batch_size` dossiers à la
  # fois ; la vague s'arrête au premier échec.
  class Wave < Marten::Model
    STATES = %w[running done failed cancelled]

    field :id, :big_int, primary_key: true, auto: true
    field :release, :many_to_one, to: PartiduoAdmin::Release, on_delete: :protect
    field :batch_size, :int, default: 1
    field :state, :string, max_size: 16, default: "running"
    field :requested_by_id, :big_int, null: true, blank: true
    field :created_at, :date_time, auto_now_add: true
    field :finished_at, :date_time, null: true, blank: true

    def state_key : String
      "admin.waves.states.#{state}"
    end
  end

  # Tâche de la file (ADR-008 D4) : type de la liste fermée, dossier,
  # paramètres JSON, demandeur, état, journal renvoyé par l'exécutant.
  class Task < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :kind, :string, max_size: 32
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, null: true, blank: true, on_delete: :protect
    field :server, :many_to_one, to: PartiduoAdmin::Server, on_delete: :protect
    field :params, :text, default: "{}"
    field :requested_by_id, :big_int, null: true, blank: true
    field :requested_by_label, :string, max_size: 255, blank: true, default: ""
    field :state, :string, max_size: 16, default: "pending"
    field :attempts, :int, default: 0
    field :wave, :many_to_one, to: PartiduoAdmin::Wave, null: true, blank: true, on_delete: :protect
    field :wave_rank, :int, null: true, blank: true
    field :claimed_at, :date_time, null: true, blank: true
    field :lease_until, :date_time, null: true, blank: true
    field :started_at, :date_time, null: true, blank: true
    field :finished_at, :date_time, null: true, blank: true
    field :result, :text, blank: true, default: ""
    field :error, :text, blank: true, default: ""
    field :log, :text, blank: true, default: ""
    # Clés de données (JSON, base64) à remettre une seule fois à
    # l'exécutant : effacées dès la réclamation, l'annulation ou la fin
    # (D-CHF-005). Jamais affichées ni journalisées.
    field :data_keys, :text, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true
    field :updated_at, :date_time, auto_now: true

    def params_json : JSON::Any
      JSON.parse(params.presence || "{}")
    end

    def param(key : String) : String?
      params_json[key]?.try { |value| value.as_s? || value.to_json }
    end

    def result_json : JSON::Any
      JSON.parse(result.presence || "{}")
    rescue JSON::ParseException
      JSON::Any.new({} of String => JSON::Any)
    end

    def state_key : String
      "admin.tasks.states.#{state}"
    end

    def kind_key : String
      "admin.tasks.kinds.#{kind.to_s.tr(".", "_")}"
    end

    def dossier_slug : String
      dossier.try(&.slug) || ""
    end

    def finished : Bool
      %w[succeeded failed cancelled].includes?(state)
    end

    # Erreur à afficher, `nil` si aucune (une chaîne vide est vraie dans un
    # gabarit de Marten).
    def error_text : String?
      error.presence
    end

    # Opération sensible : mode de validation transmis à l'exécutant
    # (`single` ou `dual`, D-VAL2-005), `nil` pour les autres tâches.
    def approval_mode_key : String?
      mode = params_json["approval_mode"]?.try(&.as_s?)
      mode && Approval::MODES.includes?(mode) ? "admin.dual_approval.modes.#{mode}" : nil
    end

    # Référence et personnes de la validation, `nil` hors opération sensible.
    def approval_summary : String?
      reference = params_json["approval_ref"]?.try(&.as_s?)
      return if reference.nil?
      approvers = params_json["approvers"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
      "#{reference} · #{approvers.join(", ")}"
    end
  end

  # Sauvegarde d'un dossier (ADR-008 D5) : `pg_dump -Fc` et archive des
  # pièces jointes, empreinte SHA-256. `frozen` : archive de fin de vie,
  # conservée dix ans et jamais élaguée.
  class Backup < Marten::Model
    KINDS  = %w[scheduled manual pre_upgrade pre_restore archive]
    STATES = %w[pending done verified failed pruned]

    field :id, :big_int, primary_key: true, auto: true
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, on_delete: :protect
    field :task, :many_to_one, to: PartiduoAdmin::Task, null: true, blank: true, on_delete: :set_null
    field :kind, :string, max_size: 16
    field :state, :string, max_size: 16, default: "pending"
    field :path, :string, max_size: 512, blank: true, default: ""
    field :media_path, :string, max_size: 512, blank: true, default: ""
    field :size_bytes, :big_int, null: true, blank: true
    field :sha256, :string, max_size: 64, blank: true, default: ""
    field :version, :string, max_size: 32, blank: true, default: ""
    field :frozen, :bool, default: false
    field :taken_at, :date_time, null: true, blank: true
    field :verified_at, :date_time, null: true, blank: true
    field :test_restored_at, :date_time, null: true, blank: true
    field :keep_until, :date_time, null: true, blank: true
    field :pruned_at, :date_time, null: true, blank: true
    # Chiffrement (D-CHF-001) : mode de la sauvegarde, figé à sa prise ;
    # empreinte de la clé, engagement sur la clé de données et clé de
    # données enveloppée (déchiffrée dans le navigateur de l'admin du
    # cabinet pour une restauration).
    field :encryption_mode, :string, max_size: 16, default: "none"
    field :key_fingerprint, :string, max_size: 64, blank: true, default: ""
    field :key_commitment, :string, max_size: 64, blank: true, default: ""
    field :wrapped_key, :text, blank: true, default: ""
    field :media_sha256, :string, max_size: 64, blank: true, default: ""
    # Dernière restauration test : `full` (relue) ou `envelope` (clé du
    # cabinet absente : empreinte et enveloppe seulement).
    field :test_check, :string, max_size: 16, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true

    def kind_key : String
      "admin.backups.kinds.#{kind}"
    end

    def encryption_key : String
      "admin.encryption.modes.#{encryption_mode}"
    end

    def cabinet_sealed : Bool
      encryption_mode == "cabinet"
    end

    def short_fingerprint : String
      key_fingerprint.to_s[0, 16]? || ""
    end

    def envelope_only : Bool
      test_check == "envelope"
    end

    def state_key : String
      "admin.backups.states.#{state}"
    end
  end

  # Demande d'opération sensible (ADR-008 D3, D5) : suppression définitive,
  # recours d'accès. Selon le réglage de la structure (D-VAL2-001), une
  # autre personne habilitée la valide (`dual`), ou le demandeur la confirme
  # seul après ré-authentification forte (`single`). `mode` : celui en
  # vigueur à la demande, puis celui de la décision.
  class Approval < Marten::Model
    MODES = %w[single dual]

    KINDS  = %w[delete admin_invite]
    STATES = %w[pending approved rejected expired]

    field :id, :big_int, primary_key: true, auto: true
    field :kind, :string, max_size: 16
    field :reference, :string, max_size: 32, unique: true
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, on_delete: :protect
    field :params, :text, default: "{}"
    field :reason, :text
    field :state, :string, max_size: 16, default: "pending"
    field :requested_by, :many_to_one, to: PartiduoAdmin::User, related: :requested_approvals, on_delete: :protect
    field :decided_by, :many_to_one, to: PartiduoAdmin::User, related: :decided_approvals, null: true, blank: true, on_delete: :protect
    field :task, :many_to_one, to: PartiduoAdmin::Task, null: true, blank: true, on_delete: :set_null
    field :created_at, :date_time, auto_now_add: true
    field :expires_at, :date_time
    field :decided_at, :date_time, null: true, blank: true
    field :mode, :string, max_size: 8, default: "dual"

    def kind_key : String
      "admin.approvals.kinds.#{kind}"
    end

    def mode_key : String
      "admin.dual_approval.modes.#{mode}"
    end

    def state_key : String
      "admin.approvals.states.#{state}"
    end

    def param(key : String) : String
      JSON.parse(params.presence || "{}")[key]?.try(&.as_s?) || ""
    end

    # `nil` si absente : une chaîne vide est vraie dans un gabarit.
    def param_email : String?
      param("email").presence
    end
  end

  # Alerte de supervision (ADR-008 D5), affichée et envoyée par courriel.
  # Une alerte ouverte par (dossier ou serveur, type) ; résolue quand la
  # condition disparaît.
  class Alert < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :kind, :string, max_size: 32
    field :severity, :string, max_size: 8, default: "warning"
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, null: true, blank: true, on_delete: :cascade
    field :server, :many_to_one, to: PartiduoAdmin::Server, null: true, blank: true, on_delete: :cascade
    field :detail, :string, max_size: 255, blank: true, default: ""
    field :opened_at, :date_time
    field :resolved_at, :date_time, null: true, blank: true
    field :notified_at, :date_time, null: true, blank: true

    def kind_key : String
      "admin.alerts.kinds.#{kind}"
    end

    # Détail affiché : l'état relevé par la supervision (`stopped`,
    # `unavailable`…) est traduit ; tout autre détail est rendu tel quel.
    def detail_text : String
      value = detail.to_s
      return value unless %w[service database].includes?(kind) && %w[running stopped ok unavailable error].includes?(value)
      I18n.t("admin.health.states.#{value}")
    end

    def subject : String
      dossier.try(&.slug) || server.try(&.name) || ""
    end
  end

  # Certificat Let's Encrypt émis pour un dossier (quota du domaine,
  # ADR-001 D2) ; `staging` : autorité de test, hors quota.
  class CertificateIssue < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :dossier, :many_to_one, to: PartiduoAdmin::Dossier, null: true, blank: true, on_delete: :set_null
    field :host, :string, max_size: 255
    field :domain, :string, max_size: 255
    field :staging, :bool, default: false
    field :issued_at, :date_time
  end
end
