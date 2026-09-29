# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Session d'administration. Jeton conservé en empreinte SHA-256 ; `level`
  # (ADR-002 D2) : 0 enrôlement, 1 mot de passe, 2 mot de passe + TOTP (ou
  # code de récupération), 3 passkey.
  class Session < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :user, :many_to_one, to: PartiduoAdmin::User, on_delete: :cascade
    field :token_digest, :string, max_size: 64, unique: true
    field :level, :int, default: 0
    field :method, :string, max_size: 16
    field :ip, :string, max_size: 64, blank: true, default: ""
    field :user_agent, :string, max_size: 255, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true
    field :last_seen_at, :date_time
    field :expires_at, :date_time
    field :revoked_at, :date_time, null: true, blank: true
    # Dernière authentification forte (au niveau exigé du rôle) : connexion,
    # élévation ou ré-authentification. Une opération sensible confirmée
    # par une seule personne l'exige récente (D-VAL2-004).
    field :strong_auth_at, :date_time, null: true, blank: true
  end

  # Défi à usage unique (WebAuthn, second facteur en attente).
  class Challenge < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :purpose, :string, max_size: 32
    field :handle_digest, :string, max_size: 64, unique: true
    field :value, :string, max_size: 255, blank: true, default: ""
    field :user, :many_to_one, to: PartiduoAdmin::User, null: true, blank: true, on_delete: :cascade
    field :created_at, :date_time, auto_now_add: true
    field :expires_at, :date_time
    field :used_at, :date_time, null: true, blank: true
  end

  # Invitation (lien remis hors bande) : premier accès ou recours.
  class Invitation < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :digest, :string, max_size: 64, unique: true
    field :user, :many_to_one, to: PartiduoAdmin::User, on_delete: :cascade
    field :created_by_id, :big_int, null: true, blank: true
    field :created_at, :date_time, auto_now_add: true
    field :expires_at, :date_time
    field :used_at, :date_time, null: true, blank: true
  end

  # Passkey enrôlée : clé publique COSE, aucun secret.
  class Passkey < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :user, :many_to_one, to: PartiduoAdmin::User, on_delete: :cascade
    field :credential_id, :string, max_size: 1400, unique: true
    field :public_key, :text
    field :cose_algorithm, :int
    field :sign_count, :big_int, default: 0
    field :backup_eligible, :bool, default: false
    field :backup_state, :bool, default: false
    field :name, :string, max_size: 100, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true
    field :last_used_at, :date_time, null: true, blank: true
  end

  # Code de récupération à usage unique (ADR-002 D7).
  class RecoveryCode < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :user, :many_to_one, to: PartiduoAdmin::User, on_delete: :cascade
    field :code_digest, :string, max_size: 64
    field :created_at, :date_time, auto_now_add: true
    field :used_at, :date_time, null: true, blank: true
  end

  # Journal d'audit en *ajout seul* (ADR-008 D2) : un déclencheur refuse
  # toute modification et toute suppression (migration 0002). Pas de clé
  # étrangère : le journal survit aux utilisateurs et aux dossiers ;
  # `actor_label` fige le nom au moment de l'action. `firm_id` : portée de
  # lecture des admins de cabinet.
  class AuditEntry < Marten::Model
    field :id, :big_int, primary_key: true, auto: true
    field :actor_id, :big_int, null: true, blank: true
    field :actor_label, :string, max_size: 255, blank: true, default: ""
    field :action, :string, max_size: 64
    field :target_type, :string, max_size: 32, blank: true, default: ""
    field :target_id, :big_int, null: true, blank: true
    field :target_label, :string, max_size: 255, blank: true, default: ""
    field :firm_id, :big_int, null: true, blank: true
    field :outcome, :string, max_size: 8, default: "ok"
    field :ip, :string, max_size: 64, blank: true, default: ""
    field :detail, :text, blank: true, default: ""
    field :created_at, :date_time, auto_now_add: true
  end
end
