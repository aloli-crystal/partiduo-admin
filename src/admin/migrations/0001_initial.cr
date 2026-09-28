# SPDX-License-Identifier: AGPL-3.0-or-later

# Schéma initial de l'administration du parc (ADR-008), généré par Marten.

class Migration::Admin::V0001 < Marten::Migration
  def plan
    create_table :admin_release do
      column :id, :big_int, primary_key: true, auto: true
      column :version, :string, max_size: 32, unique: true
      column :notes, :text, default: ""
      column :is_default, :bool, default: false
      column :created_at, :date_time
    end

    create_table :admin_server do
      column :id, :big_int, primary_key: true, auto: true
      column :name, :string, max_size: 64, unique: true
      column :hostname, :string, max_size: 255
      column :domain, :string, max_size: 255
      column :token_digest, :string, max_size: 64, unique: true
      column :active, :bool, default: true
      column :agent_version, :string, max_size: 32, default: ""
      column :agent_mode, :string, max_size: 16, default: ""
      column :last_seen_at, :date_time, null: true
      column :disk_total_bytes, :big_int, null: true
      column :disk_free_bytes, :big_int, null: true
      column :created_at, :date_time
      column :updated_at, :date_time
    end

    create_table :admin_audit_entry do
      column :id, :big_int, primary_key: true, auto: true
      column :actor_id, :big_int, null: true
      column :actor_label, :string, max_size: 255, default: ""
      column :action, :string, max_size: 64
      column :target_type, :string, max_size: 32, default: ""
      column :target_id, :big_int, null: true
      column :target_label, :string, max_size: 255, default: ""
      column :firm_id, :big_int, null: true
      column :outcome, :string, max_size: 8, default: "ok"
      column :ip, :string, max_size: 64, default: ""
      column :detail, :text, default: ""
      column :created_at, :date_time
    end

    create_table :admin_firm do
      column :id, :big_int, primary_key: true, auto: true
      column :name, :string, max_size: 150, unique: true
      column :siren, :string, max_size: 9, default: ""
      column :email, :string, max_size: 254, default: ""
      column :active, :bool, default: true
      column :created_at, :date_time
      column :updated_at, :date_time
    end

    create_table :admin_user do
      column :id, :big_int, primary_key: true, auto: true
      column :email, :string, max_size: 254, unique: true
      column :first_name, :string, max_size: 100, default: ""
      column :last_name, :string, max_size: 100, default: ""
      column :locale, :string, max_size: 8, default: "fr"
      column :role, :string, max_size: 16
      column :password_digest, :string, max_size: 128, null: true
      column :password_changed_at, :date_time, null: true
      column :totp_secret, :string, max_size: 64, null: true
      column :totp_pending_secret, :string, max_size: 64, null: true
      column :totp_enabled_at, :date_time, null: true
      column :last_otp_counter, :big_int, null: true
      column :failed_attempts, :int, default: 0
      column :last_failed_at, :date_time, null: true
      column :locked_at, :date_time, null: true
      column :active, :bool, default: true
      column :last_login_at, :date_time, null: true
      column :created_at, :date_time
      column :updated_at, :date_time
      column :firm_id, :reference, to_table: :admin_firm, to_column: :id, null: true
    end

    create_table :admin_payer do
      column :id, :big_int, primary_key: true, auto: true
      column :kind, :string, max_size: 16
      column :name, :string, max_size: 150
      column :siren, :string, max_size: 9, default: ""
      column :vat_number, :string, max_size: 20, default: ""
      column :street, :string, max_size: 200, default: ""
      column :postcode, :string, max_size: 16, default: ""
      column :city, :string, max_size: 100, default: ""
      column :country, :string, max_size: 2, default: "FR"
      column :contact_name, :string, max_size: 150, default: ""
      column :contact_email, :string, max_size: 254, default: ""
      column :contact_phone, :string, max_size: 32, default: ""
      column :created_at, :date_time
      column :updated_at, :date_time
      column :firm_id, :reference, to_table: :admin_firm, to_column: :id
    end

    create_table :admin_session do
      column :id, :big_int, primary_key: true, auto: true
      column :token_digest, :string, max_size: 64, unique: true
      column :level, :int, default: 0
      column :method, :string, max_size: 16
      column :ip, :string, max_size: 64, default: ""
      column :user_agent, :string, max_size: 255, default: ""
      column :created_at, :date_time
      column :last_seen_at, :date_time
      column :expires_at, :date_time
      column :revoked_at, :date_time, null: true
      column :user_id, :reference, to_table: :admin_user, to_column: :id
    end

    create_table :admin_challenge do
      column :id, :big_int, primary_key: true, auto: true
      column :purpose, :string, max_size: 32
      column :handle_digest, :string, max_size: 64, unique: true
      column :value, :string, max_size: 255, default: ""
      column :created_at, :date_time
      column :expires_at, :date_time
      column :used_at, :date_time, null: true
      column :user_id, :reference, to_table: :admin_user, to_column: :id, null: true
    end

    create_table :admin_invitation do
      column :id, :big_int, primary_key: true, auto: true
      column :digest, :string, max_size: 64, unique: true
      column :created_by_id, :big_int, null: true
      column :created_at, :date_time
      column :expires_at, :date_time
      column :used_at, :date_time, null: true
      column :user_id, :reference, to_table: :admin_user, to_column: :id
    end

    create_table :admin_passkey do
      column :id, :big_int, primary_key: true, auto: true
      column :credential_id, :string, max_size: 1400, unique: true
      column :public_key, :text
      column :cose_algorithm, :int
      column :sign_count, :big_int, default: 0
      column :backup_eligible, :bool, default: false
      column :backup_state, :bool, default: false
      column :name, :string, max_size: 100, default: ""
      column :created_at, :date_time
      column :last_used_at, :date_time, null: true
      column :user_id, :reference, to_table: :admin_user, to_column: :id
    end

    create_table :admin_recovery_code do
      column :id, :big_int, primary_key: true, auto: true
      column :code_digest, :string, max_size: 64
      column :created_at, :date_time
      column :used_at, :date_time, null: true
      column :user_id, :reference, to_table: :admin_user, to_column: :id
    end

    create_table :admin_dossier do
      column :id, :big_int, primary_key: true, auto: true
      column :slug, :string, max_size: 40, unique: true
      column :label, :string, max_size: 150
      column :regime, :string, max_size: 2
      column :locale, :string, max_size: 8, default: "fr"
      column :siren, :string, max_size: 9, default: ""
      column :vat_number, :string, max_size: 20, default: ""
      column :modules, :string, max_size: 255, default: ""
      column :extensions, :string, max_size: 255, default: ""
      column :admin_email, :string, max_size: 254
      column :version, :string, max_size: 32, default: ""
      column :database, :string, max_size: 63, default: ""
      column :state, :string, max_size: 16, default: "creating"
      column :backup_schedule, :string, max_size: 8, default: "daily"
      column :backup_retention_days, :int, default: 30
      column :test_restore_days, :int, default: 30
      column :service_state, :string, max_size: 16, default: ""
      column :database_state, :string, max_size: 16, default: ""
      column :cert_expires_at, :date_time, null: true
      column :health_checked_at, :date_time, null: true
      column :suspended_at, :date_time, null: true
      column :archived_at, :date_time, null: true
      column :retention_until, :date_time, null: true
      column :deleted_at, :date_time, null: true
      column :created_at, :date_time
      column :updated_at, :date_time
      column :server_id, :reference, to_table: :admin_server, to_column: :id
      column :firm_id, :reference, to_table: :admin_firm, to_column: :id
      column :payer_id, :reference, to_table: :admin_payer, to_column: :id
    end

    create_table :admin_assignment do
      column :id, :big_int, primary_key: true, auto: true
      column :created_at, :date_time
      column :user_id, :reference, to_table: :admin_user, to_column: :id
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id
    end

    create_table :admin_wave do
      column :id, :big_int, primary_key: true, auto: true
      column :batch_size, :int, default: 1
      column :state, :string, max_size: 16, default: "running"
      column :requested_by_id, :big_int, null: true
      column :created_at, :date_time
      column :finished_at, :date_time, null: true
      column :release_id, :reference, to_table: :admin_release, to_column: :id
    end

    create_table :admin_task do
      column :id, :big_int, primary_key: true, auto: true
      column :kind, :string, max_size: 32
      column :params, :text, default: "{}"
      column :requested_by_id, :big_int, null: true
      column :requested_by_label, :string, max_size: 255, default: ""
      column :state, :string, max_size: 16, default: "pending"
      column :attempts, :int, default: 0
      column :wave_rank, :int, null: true
      column :claimed_at, :date_time, null: true
      column :lease_until, :date_time, null: true
      column :started_at, :date_time, null: true
      column :finished_at, :date_time, null: true
      column :result, :text, default: ""
      column :error, :text, default: ""
      column :log, :text, default: ""
      column :created_at, :date_time
      column :updated_at, :date_time
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id, null: true
      column :server_id, :reference, to_table: :admin_server, to_column: :id
      column :wave_id, :reference, to_table: :admin_wave, to_column: :id, null: true
    end

    create_table :admin_backup do
      column :id, :big_int, primary_key: true, auto: true
      column :kind, :string, max_size: 16
      column :state, :string, max_size: 16, default: "pending"
      column :path, :string, max_size: 512, default: ""
      column :media_path, :string, max_size: 512, default: ""
      column :size_bytes, :big_int, null: true
      column :sha256, :string, max_size: 64, default: ""
      column :version, :string, max_size: 32, default: ""
      column :frozen, :bool, default: false
      column :taken_at, :date_time, null: true
      column :verified_at, :date_time, null: true
      column :test_restored_at, :date_time, null: true
      column :keep_until, :date_time, null: true
      column :pruned_at, :date_time, null: true
      column :created_at, :date_time
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id
      column :task_id, :reference, to_table: :admin_task, to_column: :id, null: true
    end

    create_table :admin_approval do
      column :id, :big_int, primary_key: true, auto: true
      column :kind, :string, max_size: 16
      column :reference, :string, max_size: 32, unique: true
      column :params, :text, default: "{}"
      column :reason, :text
      column :state, :string, max_size: 16, default: "pending"
      column :created_at, :date_time
      column :expires_at, :date_time
      column :decided_at, :date_time, null: true
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id
      column :requested_by_id, :reference, to_table: :admin_user, to_column: :id
      column :decided_by_id, :reference, to_table: :admin_user, to_column: :id, null: true
      column :task_id, :reference, to_table: :admin_task, to_column: :id, null: true
    end

    create_table :admin_alert do
      column :id, :big_int, primary_key: true, auto: true
      column :kind, :string, max_size: 32
      column :severity, :string, max_size: 8, default: "warning"
      column :detail, :string, max_size: 255, default: ""
      column :opened_at, :date_time
      column :resolved_at, :date_time, null: true
      column :notified_at, :date_time, null: true
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id, null: true
      column :server_id, :reference, to_table: :admin_server, to_column: :id, null: true
    end

    create_table :admin_certificate_issue do
      column :id, :big_int, primary_key: true, auto: true
      column :host, :string, max_size: 255
      column :domain, :string, max_size: 255
      column :staging, :bool, default: false
      column :issued_at, :date_time
      column :dossier_id, :reference, to_table: :admin_dossier, to_column: :id, null: true
    end

    add_unique_constraint :admin_assignment, :admin_assignment_unique, [:user_id, :dossier_id]
  end
end
