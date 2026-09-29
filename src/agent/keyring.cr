# SPDX-License-Identifier: AGPL-3.0-or-later

require "base64"
require "../shared/backup_crypto"

module PartiduoAgent
  alias BackupCrypto = PartiduoAdmin::BackupCrypto

  # Clés dont dispose l'exécutant pour une tâche (D-CHF-003, D-CHF-006) :
  #
  # * la clé du serveur (`--server-key`, créée au premier usage, 0600, dans
  #   l'état de l'exécutant) ;
  # * les clés de données des sauvegardes que la tâche vient de prendre
  #   (journal de reprise, clés `secret.*`, effacées à la fin de la tâche) ;
  # * les clés de données remises par l'administration pour lire une
  #   sauvegarde chiffrée par la clé du cabinet (déchiffrées dans le
  #   navigateur de l'admin du cabinet, remises une seule fois, gardées en
  #   mémoire).
  #
  # La clé privée d'un cabinet n'est jamais ici.
  class Keyring
    SECRET_PREFIX = "secret."

    @server_key : BackupCrypto::ServerKey?
    @given : Array(Bytes)

    def initialize(@config : Config, @journal : Journal, data_keys : Array(String) = [] of String,
                   @log : Proc(String, Nil) = ->(_line : String) { nil })
      @given = data_keys.compact_map { |value| decode(value) }.select { |key| key.size == BackupCrypto::KEY_SIZE }
    end

    # Clé du serveur. À blanc : une clé éphémère, jamais écrite.
    def server_key : BackupCrypto::ServerKey
      @server_key ||= begin
        if @config.mode.dry_run?
          BackupCrypto::ServerKey.new(BackupCrypto.random_key)
        else
          key, created = BackupCrypto::ServerKey.load_or_create(@config.server_key_path)
          if created
            @log.call("clé du serveur créée (#{@config.server_key_path}, empreinte #{key.fingerprint[0, 16]}…) : " \
                      "copiez-la hors du serveur, sans elle les sauvegardes « clé du serveur » sont perdues")
          end
          key
        end
      end
    rescue ex : BackupCrypto::Error | File::Error
      raise StepError.new("clé du serveur : #{ex.message}")
    end

    # Clés de données connues : remises par l'administration, puis celles du
    # journal de la tâche.
    def data_keys : Array(Bytes)
      @given + @journal.values.compact_map do |key, value|
        decode(value) if key.starts_with?(SECRET_PREFIX)
      end
    end

    private def decode(value : String) : Bytes?
      Base64.decode(value)
    rescue Base64::Error
      nil
    end

    # Clé de données connue dont l'engagement est `commitment` (hexadécimal).
    def data_key?(commitment : String) : Bytes?
      data_keys.find { |key| BackupCrypto.commitment(key).hexstring == commitment }
    end

    # Clé de données d'un fichier chiffré, d'après son en-tête.
    def data_key_for(header : BackupCrypto::Header) : Bytes
      if header.mode == BackupCrypto::SERVER
        key = server_key
        unless BackupCrypto.same?(key.id, header.key_id)
          raise StepError.new("sauvegarde chiffrée par une autre clé du serveur (#{header.key_id.hexstring[0, 16]}…) : " \
                              "restaurez la clé d'origine avec --server-key", "refused")
        end
        return key.unwrap(header.wrapped)
      end
      data_key?(header.commitment.hexstring) ||
        raise StepError.new("sauvegarde chiffrée par la clé du cabinet (#{header.key_id.hexstring[0, 16]}…) : " \
                            "la restauration exige que l'admin du cabinet fournisse sa clé", "key_required")
    rescue ex : BackupCrypto::Error
      raise StepError.new("sauvegarde chiffrée : #{ex.message}", "refused")
    end

    # Ouvre un fichier chiffré en flux déchiffrant.
    def open(path : String, & : BackupCrypto::Reader -> T) : T forall T
      File.open(path, "rb") do |file|
        header = BackupCrypto::Header.read(file)
        yield BackupCrypto::Reader.new(file, header, data_key_for(header))
      end
    rescue ex : BackupCrypto::Error
      raise StepError.new("sauvegarde chiffrée #{File.basename(path)} : #{ex.message}", "refused")
    rescue ex : File::Error
      raise StepError.new("sauvegarde illisible : #{ex.message}")
    end
  end
end
