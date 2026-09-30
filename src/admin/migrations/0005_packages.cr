# SPDX-License-Identifier: AGPL-3.0-or-later

# Serveurs FreeBSD : chaque dossier est servi par l'un des deux paquets qui
# cohabitent, `partiduo-app` (`app`) ou `partiduo-app-devel` (`devel`). La
# mise à jour des paquets relève de beryl et chaque instance se migre à son
# démarrage : l'administration ne publie plus de versions et ne monte plus
# les dossiers par vagues (tables `admin_release`, `admin_wave` et colonnes
# de vague des tâches retirées). `admin_dossier.version` reste : c'est la
# version relevée sur l'instance, affichée.
class Migration::Admin::V0005 < Marten::Migration
  depends_on :admin, "0004_dual_approval"

  def plan
    add_column :admin_dossier, :package, :string, max_size: 8, default: "app"

    # Tâches de vague encore retenues : annulées, l'exécutant n'en connaît
    # plus le type.
    execute(<<-SQL, "SELECT 1")
      UPDATE admin_task SET state = 'cancelled', error = 'wave_removed'
       WHERE state = 'waiting' OR (kind = 'instance.upgrade' AND state = 'pending')
      SQL

    remove_column :admin_task, :wave_id
    remove_column :admin_task, :wave_rank
    delete_table :admin_wave
    delete_table :admin_release
  end
end
