# SPDX-License-Identifier: AGPL-3.0-or-later

# Protocole entre l'administration et l'exécutant (ADR-008 D4), partagé par
# les deux binaires : liste fermée des types de tâches, états, version de
# l'API. Aucune dépendance à Marten : l'exécutant n'embarque que ce fichier.
module PartiduoAdmin
  module Protocol
    # Version de l'API de l'exécutant (`/api/agent/v1/…`). Retirer ou renommer
    # un type de tâche, une clé ou un état incrémente la majeure ; en ajouter
    # incrémente la mineure (1.1.0 : chiffrement des sauvegardes — clés
    # `encryption`, `backup_encryption`, `media_sha256`, `key_provided` des
    # paramètres, `secrets.data_keys` de la tâche réclamée, D-CHF-010 ;
    # 1.2.0 : `approval_mode` des opérations sensibles, D-VAL2-005 ;
    # 2.0.0 : type `instance.upgrade` et état `waiting` retirés, paramètre
    # `version` remplacé par `package` — la mise à jour des paquets relève
    # de beryl, chaque instance se migre à son démarrage).
    API_VERSION = "2.0.0"

    # Mode de validation d'une opération sensible (`instance.delete`,
    # `instance.admin_invite`) : `single`, une personne qui a confirmé seule
    # après ré-authentification ; `dual`, deux personnes distinctes. Absent
    # (administration antérieure à 1.2.0) : `dual`.
    APPROVAL_MODES = %w[single dual]

    # Mineure du contrat `manage instance` qui accepte `admin-invite
    # --approval-mode single|dual` et un seul nom en mode `single`
    # (contrat 1.1.0, B-VAL2-001 levé).
    APPROVAL_MODE_MINOR = 1

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
      instance.admin_invite
      backup.run
      backup.prune
      backup.test_restore
      backup.restore
      supervision.check
    ]

    # États d'une tâche : en attente, en cours, réussie, échouée, annulée.
    STATES = %w[pending running succeeded failed cancelled]

    # Durée pendant laquelle une tâche réclamée reste à l'exécutant qui l'a
    # prise ; chaque compte rendu la prolonge. Échue, la tâche est reprise
    # (par le même serveur : elle est rattachée à lui).
    LEASE_SECONDS = 600

    # Conservation d'une archive (Code de commerce, art. L123-22 ; ADR-008
    # D5) : l'exécutant la revérifie lui-même avant une suppression
    # définitive ou l'effacement d'une archive (D-CRA-007).
    ARCHIVE_RETENTION_YEARS = 10

    # Nom d'un fichier d'archive : `archive-<horodatage>.dump` ou
    # `archive-<horodatage>.media.tar.gz` (horodatage UTC de la prise).
    ARCHIVE_FILE = /\Aarchive-(\d{8}T\d{6}Z)\./

    # Date de prise d'un fichier d'archive, d'après son nom ; `nil` pour un
    # autre fichier.
    def self.archive_taken_at(path : String) : Time?
      match = ARCHIVE_FILE.match(File.basename(path)) || return
      Time.parse(match[1], "%Y%m%dT%H%M%SZ", Time::Location::UTC)
    rescue Time::Format::Error
      nil
    end

    # Modules officiels de partiduo-app (ADR-006, ADR-007).
    MODULES = %w[accounting invoicing analytic stock followup micro liberal]

    # Sous-domaine d'un dossier : même règle que `partiduo-provision`.
    SLUG = /\A[a-z][a-z0-9-]{0,39}\z/

    # Code d'extension (ADR-003) : même règle que `partiduo-provision`.
    CODE = /\A[a-z][a-z0-9_]*\z/

    # Paquet FreeBSD qui sert une instance : `app` (`partiduo-app`) ou
    # `devel` (`partiduo-app-devel`), exclusifs : un seul par serveur, aux
    # mêmes emplacements.
    # Liste fermée : la valeur choisit un paquet, jamais un chemin.
    PACKAGES = %w[app devel]

    # Domaine des dossiers d'un serveur : même règle que `partiduo-provision`.
    DOMAIN = /\A[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\z/

    def self.valid_domain?(domain : String) : Bool
      DOMAIN.matches?(domain)
    end

    def self.valid_package?(package : String) : Bool
      PACKAGES.includes?(package)
    end

    def self.valid_kind?(kind : String) : Bool
      KINDS.includes?(kind)
    end

    # Sous-domaines réservés : l'administration elle-même (`admin.<domaine>`,
    # base `partiduo_admin`, ADR-008 D1) et le site public.
    RESERVED_SLUGS = %w[admin www]

    # Préfixe réservé aux bases temporaires des restaurations test
    # (`partiduo_rt_<dossier>_<tâche>`, `partiduo_adm_rt_…` en mode local) :
    # un dossier `rt-x-5` aurait la base de la restauration test du dossier
    # `x`, tâche 5, que l'exécutant supprime.
    RESERVED_PREFIX = "rt-"

    def self.valid_slug?(slug : String) : Bool
      SLUG.matches?(slug) && !slug.ends_with?('-') && !RESERVED_SLUGS.includes?(slug) &&
        !slug.starts_with?(RESERVED_PREFIX)
    end

    # Nom de la base d'un dossier. Le mode local de l'exécutant préfixe
    # `partiduo_adm_` pour ne jamais toucher une autre base de la machine.
    def self.database_for(slug : String, local : Bool = false) : String
      (local ? "partiduo_adm_" : "partiduo_") + slug.tr("-", "_")
    end
  end
end
