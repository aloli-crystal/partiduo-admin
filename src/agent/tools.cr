# SPDX-License-Identifier: AGPL-3.0-or-later

require "option_parser"
require "base64"

module PartiduoAgent
  # Commandes locales de l'exécutant, sans administration (D-CHF-009) :
  #
  # * `partiduo-agent decrypt` : déchiffre une sauvegarde hors de Partiduo,
  #   sur le poste du cabinet (clé privée) ou sur le serveur (clé du
  #   serveur) ;
  # * `partiduo-agent inspect` : en-tête d'une sauvegarde chiffrée ;
  # * `partiduo-agent server-key` : crée au besoin la clé du serveur et
  #   affiche son empreinte.
  module Tools
    COMMANDS = %w[decrypt inspect server-key]

    def self.command?(args : Array(String)) : Bool
      COMMANDS.includes?(args.first?)
    end

    # Rend le code de sortie.
    def self.run(args : Array(String), output : IO = STDOUT, error : IO = STDERR) : Int32
      case args.first
      when "decrypt"    then decrypt(args[1..], output)
      when "inspect"    then inspect(args[1..], output)
      when "server-key" then server_key(args[1..], output)
      else                   2
      end
    rescue ex : BackupCrypto::Error | StepError | File::Error | OptionParser::Exception | ArgumentError
      error.puts "partiduo-agent : #{ex.message}"
      1
    end

    def self.decrypt(args : Array(String), output : IO) : Int32
      private_key = server_key = passphrase_file = data_key_file = ""
      files = [] of String
      OptionParser.parse(args) do |parser|
        parser.banner = "Usage : partiduo-agent decrypt (--private-key PEM [--passphrase-file F] | --server-key F | " \
                        "--data-key-file F) SOURCE.enc DESTINATION"
        parser.on("--private-key PEM", "clé privée du cabinet (PKCS#8, chiffrée ou non)") { |value| private_key = value }
        parser.on("--passphrase-file F", "phrase de passe de la clé privée (sinon : PARTIDUO_KEY_PASSPHRASE)") { |value| passphrase_file = value }
        parser.on("--server-key F", "clé du serveur (64 chiffres hexadécimaux)") { |value| server_key = value }
        parser.on("--data-key-file F", "clé de données en clair (32 octets, sortie d'openssl pkeyutl)") { |value| data_key_file = value }
        parser.unknown_args { |rest| files = rest }
      end
      raise ArgumentError.new("SOURCE et DESTINATION attendus") unless files.size == 2
      source, destination = files
      header = BackupCrypto.read_header(source)
      data_key = if !private_key.empty?
                   passphrase = passphrase_file.empty? ? (ENV["PARTIDUO_KEY_PASSPHRASE"]? || "") : File.read(passphrase_file).chomp
                   key = BackupCrypto::PrivateKey.new(File.read(private_key), passphrase)
                   unless BackupCrypto.same?(key.id, header.key_id)
                     raise BackupCrypto::Error.new("cette clé n'est pas celle de la sauvegarde (empreinte attendue #{header.key_id.hexstring})")
                   end
                   key.unwrap(header.wrapped)
                 elsif !server_key.empty?
                   BackupCrypto::ServerKey.load(server_key).unwrap(header.wrapped)
                 elsif !data_key_file.empty?
                   File.read(data_key_file).to_slice
                 else
                   raise ArgumentError.new("indiquez --private-key, --server-key ou --data-key-file")
                 end
      partial = "#{destination}.part"
      File.open(source, "rb") do |file|
        reader = BackupCrypto::Reader.new(file, BackupCrypto::Header.read(file), data_key)
        File.open(partial, "wb", perm: 0o600) { |target| IO.copy(reader, target) }
      end
      File.rename(partial, destination)
      output.puts "#{destination} : déchiffré et authentifié"
      0
    ensure
      File.delete(partial) if partial && File.exists?(partial)
    end

    def self.inspect(args : Array(String), output : IO) : Int32
      raise ArgumentError.new("Usage : partiduo-agent inspect SOURCE.enc") unless args.size == 1
      header = BackupCrypto.check_structure(args.first)
      output.puts "format 1, #{header.mode == BackupCrypto::SERVER ? "clé du serveur" : "clé du cabinet (RSA-OAEP)"}"
      output.puts "empreinte de la clé : #{header.key_id.hexstring}"
      output.puts "engagement : #{header.commitment.hexstring}"
      output.puts "segments : #{header.chunk_size} octets"
      0
    end

    def self.server_key(args : Array(String), output : IO) : Int32
      path = ""
      state_dir = ENV["PARTIDUO_AGENT_STATE"]? || "/var/lib/partiduo-agent"
      OptionParser.parse(args) do |parser|
        parser.banner = "Usage : partiduo-agent server-key [--state-dir RÉP | --server-key FICHIER]"
        parser.on("--state-dir RÉP", "état de l'exécutant") { |value| state_dir = value }
        parser.on("--server-key FICHIER", "clé du serveur") { |value| path = value }
      end
      path = File.join(state_dir, "backup-server.key") if path.empty?
      key, created = BackupCrypto::ServerKey.load_or_create(path)
      output.puts "#{created ? "clé créée" : "clé existante"} : #{path}"
      output.puts "empreinte : #{key.fingerprint}"
      output.puts "Copiez ce fichier hors du serveur (coffre) : sans lui, les sauvegardes « clé du serveur » sont illisibles." if created
      0
    end
  end
end
