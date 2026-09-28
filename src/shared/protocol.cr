# SPDX-License-Identifier: AGPL-3.0-or-later

# Protocole entre l'administration et l'exécutant (ADR-008 D4), partagé par
# les deux binaires : liste fermée des types de tâches, états, version de
# l'API. Aucune dépendance à Marten : l'exécutant n'embarque que ce fichier.
module PartiduoAdmin
  module Protocol
    # Version de l'API de l'exécutant (`/api/agent/v1/…`). Retirer ou renommer
    # un type de tâche, une clé ou un état incrémente la majeure.
    API_VERSION = "1.0.0"

    # Version majeure du contrat `manage instance` de partiduo-app que
    # l'exécutant sait parler (doc/api/instance-cli.adoc de partiduo-app).
    INSTANCE_CLI_MAJOR = 1

    # Liste *fermée* des types de tâches : l'exécutant refuse tout autre type,
    # et aucun ne porte de commande arbitraire.
    KINDS = %w[
      instance.create
      instance.modules
      instance.suspend
      instance.resume
      instance.archive
      instance.restore_archive
      instance.delete
      instance.upgrade
      instance.admin_invite
      backup.run
      backup.prune
      backup.test_restore
      backup.restore
      supervision.check
    ]

    # États d'une tâche : en attente, en cours, réussie, échouée, annulée ;
    # `waiting` : tâche d'une vague retenue jusqu'à la fin du lot précédent
    # (jamais remise à l'exécutant).
    STATES = %w[waiting pending running succeeded failed cancelled]

    # Durée pendant laquelle une tâche réclamée reste à l'exécutant qui l'a
    # prise ; chaque compte rendu la prolonge. Échue, la tâche est reprise
    # (par le même serveur : elle est rattachée à lui).
    LEASE_SECONDS = 600

    # Modules officiels de partiduo-app (ADR-006, ADR-007).
    MODULES = %w[accounting invoicing analytic stock followup micro liberal]

    # Sous-domaine d'un dossier : même règle que `partiduo-provision`.
    SLUG = /\A[a-z][a-z0-9-]{0,39}\z/

    # Code d'extension (ADR-003) : même règle que `partiduo-provision`.
    CODE = /\A[a-z][a-z0-9_]*\z/

    def self.valid_kind?(kind : String) : Bool
      KINDS.includes?(kind)
    end

    def self.valid_slug?(slug : String) : Bool
      SLUG.matches?(slug) && !slug.ends_with?('-')
    end

    # Nom de la base d'un dossier. Le mode local de l'exécutant préfixe
    # `partiduo_adm_` pour ne jamais toucher une autre base de la machine.
    def self.database_for(slug : String, local : Bool = false) : String
      (local ? "partiduo_adm_" : "partiduo_") + slug.tr("-", "_")
    end
  end
end
