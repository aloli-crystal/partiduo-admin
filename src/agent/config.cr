# SPDX-License-Identifier: AGPL-3.0-or-later

require "option_parser"
require "uri"

module PartiduoAgent
  VERSION = "0.1.0"

  # Modes de l'exécutant :
  #
  # * `dry-run` (à blanc) : rien n'est exécuté ; chaque geste est simulé et
  #   inscrit au journal renvoyé à l'admin (specs, répétition) ;
  # * `local` : développement — opère réellement sur des bases
  #   `partiduo_adm_*` de la machine, sans vhost, service rc.d ni Let's
  #   Encrypt : les fichiers de service sont produits dans `work_dir` ;
  # * `production` : serveur d'hébergement FreeBSD (sudo, service(8),
  #   acme.sh), par les enveloppes de `helpers_dir`.
  enum Mode
    DryRun
    Local
    Production

    def label : String
      case self
      in DryRun     then "dry-run"
      in Local      then "local"
      in Production then "production"
      end
    end

    def self.parse(value : String) : Mode
      case value
      when "dry-run", "dry_run", "dryrun" then DryRun
      when "local"                        then Local
      when "production"                   then Production
      else                                     raise ArgumentError.new("mode inconnu : #{value} (dry-run, local, production)")
      end
    end
  end

  class Config
    property admin_url : String = ENV["PARTIDUO_ADMIN_URL"]? || "https://admin.partiduo.app"
    property token : String = ENV["PARTIDUO_AGENT_TOKEN"]? || ""
    property mode : Mode = Mode::DryRun
    property state_dir : String = ENV["PARTIDUO_AGENT_STATE"]? || "/var/db/partiduo-agent"
    property work_dir : String = File.join(Dir.tempdir, "partiduo-agent")
    property backup_dir : String = "/var/backups/partiduo"
    # Mode local : outils des paquets `app` (`partiduo-app`) et `devel`
    # (`partiduo-app-devel`), liens installés par les paquets dans
    # /usr/local/bin ; ceux de `devel` vides : ceux de `app`. En production,
    # les enveloppes prennent ceux du paquet de l'instance
    # (/usr/local/lib/partiduo[-devel]/bin).
    property manage : String = ENV["PARTIDUO_MANAGE"]? || "/usr/local/bin/partiduo-manage"
    property provision : String = ENV["PARTIDUO_PROVISION"]? || "/usr/local/bin/partiduo-provision"
    property manage_devel : String = ENV["PARTIDUO_MANAGE_DEVEL"]? || "/usr/local/bin/partiduo-devel-manage"
    property provision_devel : String = ENV["PARTIDUO_PROVISION_DEVEL"]? || "/usr/local/bin/partiduo-devel-provision"
    property system_user : String = "partiduo"
    # Domaine des dossiers de ce serveur (`<sous-domaine>.<domaine>`) : les
    # hôtes reçus de l'administration doivent lui correspondre (D-AFN-004).
    # Obligatoire en production ; ailleurs, celui de la tâche.
    property domain : String = ""
    # Production : scripts enveloppes possédés par root (D-AFN-002).
    property helpers_dir : String = "/usr/local/libexec/partiduo-agent"
    property pg_socket : String = "/tmp"
    property acme_email : String = ""
    property acme_staging : Bool = false
    # Remise des invitations par le serveur (D-CRA-003) : commande de
    # courriel (sans shell, message sur l'entrée standard, destinataire en
    # dernier argument) et expéditeur. Vide : le lien est rendu à
    # l'administration, qui l'envoie (D-ADM-009).
    property mail_command : String = ""
    property mail_from : String = ""
    # Clé du serveur des sauvegardes chiffrées (D-CHF-003) : vide, le
    # fichier `backup-server.key` de `state_dir`.
    property server_key_file : String = ""
    property poll_interval : Time::Span = 15.seconds
    property once : Bool = false
    # À blanc : fait échouer la première opération dont le nom contient
    # cette valeur (specs des échecs et de la reprise).
    property fail_on : String? = nil

    def self.parse(args : Array(String)) : Config
      config = new
      token_file = nil
      OptionParser.parse(args) do |parser|
        parser.banner = "Usage : partiduo-agent [options]\n\nExécutant de partiduo-admin (ADR-008 D4)."
        parser.on("--admin-url URL", "adresse de l'administration (HTTPS)") { |value| config.admin_url = value }
        parser.on("--token-file FICHIER", "fichier du jeton du serveur") { |value| token_file = value }
        parser.on("--mode MODE", "dry-run, local ou production (défaut : dry-run)") { |value| config.mode = Mode.parse(value) }
        parser.on("--state-dir RÉP", "état des tâches en cours (reprise)") { |value| config.state_dir = value }
        parser.on("--work-dir RÉP", "mode local : fichiers produits") { |value| config.work_dir = value }
        parser.on("--backup-dir RÉP", "répertoire des sauvegardes") { |value| config.backup_dir = value }
        parser.on("--manage CHEMIN", "mode local : partiduo-manage du paquet app") { |value| config.manage = value }
        parser.on("--provision CHEMIN", "mode local : partiduo-provision du paquet app") { |value| config.provision = value }
        parser.on("--manage-devel CHEMIN", "mode local : partiduo-manage du paquet devel") { |value| config.manage_devel = value }
        parser.on("--provision-devel CHEMIN", "mode local : partiduo-provision du paquet devel") do |value|
          config.provision_devel = value
        end
        parser.on("--system-user NOM", "compte système des instances") { |value| config.system_user = value }
        parser.on("--domain DOMAINE", "domaine des dossiers de ce serveur (obligatoire en production)") { |value| config.domain = value }
        parser.on("--helpers-dir RÉP", "production : scripts enveloppes de sudo") { |value| config.helpers_dir = value }
        parser.on("--pg-socket RÉP", "socket PostgreSQL") { |value| config.pg_socket = value }
        parser.on("--acme-email ADRESSE", "compte ACME") { |value| config.acme_email = value }
        parser.on("--acme-staging", "autorité de test de Let's Encrypt") { config.acme_staging = true }
        parser.on("--mail-command COMMANDE", "remise des invitations par le serveur (ex. « /usr/sbin/sendmail -oi »)") do |value|
          config.mail_command = value
        end
        parser.on("--mail-from ADRESSE", "expéditeur des invitations remises par le serveur") { |value| config.mail_from = value }
        parser.on("--server-key FICHIER", "clé du serveur des sauvegardes chiffrées (défaut : <state-dir>/backup-server.key)") do |value|
          config.server_key_file = value
        end
        parser.on("--poll SECONDES", "intervalle d'interrogation") { |value| config.poll_interval = value.to_i.seconds }
        parser.on("--once", "traite au plus une tâche puis s'arrête") { config.once = true }
        parser.on("--fail-on TEXTE", "à blanc seulement : fait échouer la première opération qui contient TEXTE " \
                                     "(répétition d'un échec)") { |value| config.fail_on = value }
        parser.on("-h", "--help", "cette aide") do
          puts parser
          exit 0
        end
      end
      if file = token_file
        config.token = File.read(file).strip
      end
      config.validate!
      config
    end

    def validate! : Nil
      raise ArgumentError.new("jeton manquant (--token-file ou PARTIDUO_AGENT_TOKEN)") if token.empty?
      uri = URI.parse(admin_url)
      host = uri.host.to_s
      local = host == "127.0.0.1" || host == "localhost" || host.ends_with?(".localhost")
      # HTTPS obligatoire (ADR-008 D4), sauf vers la machine elle-même.
      raise ArgumentError.new("l'administration doit être jointe en HTTPS : #{admin_url}") unless uri.scheme == "https" || local
      raise ArgumentError.new("le mode production exige HTTPS") if mode.production? && uri.scheme != "https"
      unless domain.empty? || PartiduoAdmin::Protocol.valid_domain?(domain)
        raise ArgumentError.new("domaine invalide : #{domain}")
      end
      raise ArgumentError.new("le mode production exige --domain") if mode.production? && domain.empty?
      validate_fail_on!
      validate_mail!
    end

    # Remise des invitations par le serveur : expéditeur obligatoire.
    private def validate_mail! : Nil
      return if mail_command.strip.empty? || InvitationMail.valid_address?(mail_from)
      raise ArgumentError.new("--mail-command exige --mail-from (adresse de l'expéditeur)")
    end

    # Échec simulé : jamais sur un vrai système.
    private def validate_fail_on! : Nil
      raise ArgumentError.new("--fail-on n'est permis qu'à blanc") if fail_on && !mode.dry_run?
    end

    def server_key_path : String
      server_key_file.presence || File.join(state_dir, "backup-server.key")
    end

    def local? : Bool
      mode.local?
    end

    def production? : Bool
      mode.production?
    end
  end
end
