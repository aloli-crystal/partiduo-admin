# SPDX-License-Identifier: AGPL-3.0-or-later

# Validation à deux au choix (DECISIONS D-VAL2-001 et suivantes) : nature de
# la structure (cabinet, gestionnaire indépendant, parc sans cabinet),
# réglage « validation à deux » par structure, mode de chaque demande,
# heure de la dernière authentification forte d'une session.
#
# Reprise : un cabinet qui compte déjà au moins deux admins actifs garde la
# validation à deux (comportement antérieur) ; les autres passent à « une
# personne », défaut de la décision du 29 septembre 2026.
class Migration::Admin::V0004 < Marten::Migration
  depends_on :admin, "0003_backup_encryption"

  def plan
    add_column :admin_firm, :kind, :string, max_size: 16, default: "cabinet"
    add_column :admin_firm, :dual_approval, :bool, default: false
    add_column :admin_firm, :dual_approval_changed_at, :date_time, null: true

    add_column :admin_approval, :mode, :string, max_size: 8, default: "dual"

    add_column :admin_session, :strong_auth_at, :date_time, null: true

    execute(<<-SQL, "SELECT 1")
      UPDATE admin_firm SET dual_approval = TRUE
       WHERE (SELECT count(*) FROM admin_user u
               WHERE u.firm_id = admin_firm.id AND u.role = 'firm_admin' AND u.active) >= 2
      SQL
    # Un seul « parc sans cabinet » : le périmètre propre du super-admin.
    execute("CREATE UNIQUE INDEX admin_firm_single_fleet ON admin_firm (kind) WHERE kind = 'fleet'",
      "DROP INDEX admin_firm_single_fleet")
  end
end
