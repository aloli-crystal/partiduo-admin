# SPDX-License-Identifier: AGPL-3.0-or-later

# Chiffrement des sauvegardes (DECISIONS D-CHF-001 à D-CHF-012) : réglage du
# cabinet (valeur par défaut de ses dossiers) et clé publique déposée par son
# admin, surcharge par dossier, mode et enveloppe de chaque sauvegarde, clés
# de données remises une seule fois à l'exécutant pour une restauration.
class Migration::Admin::V0003 < Marten::Migration
  depends_on :admin, "0002_audit_append_only"

  def plan
    add_column :admin_firm, :backup_encryption, :string, max_size: 16, default: "server"
    add_column :admin_firm, :backup_public_key, :text, default: ""
    add_column :admin_firm, :backup_key_fingerprint, :string, max_size: 64, default: ""
    add_column :admin_firm, :backup_key_set_at, :date_time, null: true

    add_column :admin_dossier, :backup_encryption, :string, max_size: 16, default: ""

    add_column :admin_backup, :encryption_mode, :string, max_size: 16, default: "none"
    add_column :admin_backup, :key_fingerprint, :string, max_size: 64, default: ""
    add_column :admin_backup, :key_commitment, :string, max_size: 64, default: ""
    add_column :admin_backup, :wrapped_key, :text, default: ""
    add_column :admin_backup, :media_sha256, :string, max_size: 64, default: ""
    add_column :admin_backup, :test_check, :string, max_size: 16, default: ""

    add_column :admin_task, :data_keys, :text, default: ""
  end
end
