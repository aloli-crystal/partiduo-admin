# SPDX-License-Identifier: AGPL-3.0-or-later

# Journal d'audit en ajout seul (ADR-008 D2) : un déclencheur refuse toute
# modification et toute suppression d'une ligne, quel que soit le chemin
# (application, psql). `TRUNCATE`, réservé au propriétaire de la table, n'est
# pas couvert (les specs vident les tables par lui ; DECISIONS D-ADM-004).
# Index de lecture par cabinet et de réclamation des tâches par serveur.
class Migration::Admin::V0002 < Marten::Migration
  depends_on :admin, "0001_initial"

  def plan
    execute(<<-SQL, "DROP FUNCTION admin_audit_entry_immutable()")
      CREATE FUNCTION admin_audit_entry_immutable() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'admin_audit_entry est en ajout seul (ADR-008 D2)'
          USING ERRCODE = 'insufficient_privilege';
      END;
      $$ LANGUAGE plpgsql
      SQL
    execute(<<-SQL, "DROP TRIGGER admin_audit_entry_immutable ON admin_audit_entry")
      CREATE TRIGGER admin_audit_entry_immutable
        BEFORE UPDATE OR DELETE ON admin_audit_entry
        FOR EACH ROW EXECUTE FUNCTION admin_audit_entry_immutable()
      SQL
    execute("CREATE INDEX admin_audit_entry_firm_created ON admin_audit_entry (firm_id, created_at)",
      "DROP INDEX admin_audit_entry_firm_created")
    execute("CREATE INDEX admin_task_claim ON admin_task (server_id, state, id)", "DROP INDEX admin_task_claim")
  end
end
