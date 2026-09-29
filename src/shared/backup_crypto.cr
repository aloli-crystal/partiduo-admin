# SPDX-License-Identifier: AGPL-3.0-or-later

require "openssl"
require "openssl/hmac"
require "digest/sha256"
require "random/secure"
require "base64"

# Liaisons de libcrypto (OpenSSL 3) : celles du shard `jose`, déjà présent
# (AES-GCM, EVP_PKEY), et, en plus, les clés PEM et RSA-OAEP. Préfixe `pd_` :
# aucun conflit avec la bibliothèque standard ni avec `jose`.
require "jose/openssl_ext"

lib LibCrypto
  PD_EVP_PKEY_RSA = 6

  alias PdPemPasswordCallback = (UInt8*, Int32, Int32, Void*) -> Int32

  fun pd_bio_new_mem_buf = BIO_new_mem_buf(buf : Void*, len : Int32) : Bio*
  fun pd_pem_read_bio_pubkey = PEM_read_bio_PUBKEY(bio : Bio*, x : EvpPKey*, cb : PdPemPasswordCallback, u : Void*) : EvpPKey
  fun pd_pem_read_bio_private_key = PEM_read_bio_PrivateKey(bio : Bio*, x : EvpPKey*, cb : PdPemPasswordCallback, u : Void*) : EvpPKey
  fun pd_evp_pkey_get_base_id = EVP_PKEY_get_base_id(pkey : EvpPKey) : Int32
  fun pd_evp_pkey_get_bits = EVP_PKEY_get_bits(pkey : EvpPKey) : Int32
  fun pd_i2d_pubkey = i2d_PUBKEY(pkey : EvpPKey, out : UInt8**) : Int32
  fun pd_evp_pkey_encrypt_init = EVP_PKEY_encrypt_init(ctx : EvpPkeyCtx) : Int32
  fun pd_evp_pkey_encrypt = EVP_PKEY_encrypt(ctx : EvpPkeyCtx, out : UInt8*, outlen : SizeT*, input : UInt8*, inlen : SizeT) : Int32
  fun pd_evp_pkey_decrypt_init = EVP_PKEY_decrypt_init(ctx : EvpPkeyCtx) : Int32
  fun pd_evp_pkey_decrypt = EVP_PKEY_decrypt(ctx : EvpPkeyCtx, out : UInt8*, outlen : SizeT*, input : UInt8*, inlen : SizeT) : Int32
  fun pd_evp_pkey_ctx_ctrl_str = EVP_PKEY_CTX_ctrl_str(ctx : EvpPkeyCtx, type : UInt8*, value : UInt8*) : Int32
  fun pd_err_clear_error = ERR_clear_error
end

module PartiduoAdmin
  # Chiffrement des sauvegardes (DECISIONS D-CHF-001 à D-CHF-012), partagé par
  # l'exécutant (chiffre, déchiffre, vérifie) et l'administration (clés
  # publiques des cabinets, contrôle d'une clé de données).
  #
  # Enveloppe hybride, format 1 (README, « Format de l'enveloppe ») :
  #
  # * une *clé de données* aléatoire de 32 octets par sauvegarde (base et
  #   pièces jointes), enveloppée soit par la clé du serveur (AES-256-GCM),
  #   soit par la clé publique du cabinet (RSA-OAEP, SHA-256) ;
  # * par fichier, une clé de fichier dérivée par HKDF-SHA256 (sel aléatoire
  #   de l'en-tête) ;
  # * le contenu en segments de 64 Kio chiffrés par AES-256-GCM (nonce :
  #   compteur de 11 octets et drapeau « dernier segment »), l'en-tête entier
  #   en données associées : tout octet modifié, tout segment déplacé, retiré
  #   ou ajouté fait échouer la lecture.
  module BackupCrypto
    # Enveloppe illisible, altérée, tronquée, ou mauvaise clé.
    class Error < Exception
    end

    MAGIC   = "PDUOBAK".to_slice
    VERSION = 1_u8

    # Modes d'enveloppe de la clé de données.
    SERVER  = 1_u8
    CABINET = 2_u8

    KEY_SIZE      =     32
    NONCE_SIZE    =     12
    TAG_SIZE      =     16
    CHUNK_SIZE    = 65_536
    MAX_CHUNK     = 16 * 1024 * 1024
    MAX_WRAPPED   = 1024
    MIN_RSA_BITS  = 3072
    HEADER_FIXED  = 7 + 1 + 1 + 4 + 32 + 32 + 32 + 2
    EXTENSION     = ".enc"
    INFO_DATA     = "partiduo-backup/1 data"
    INFO_COMMIT   = "partiduo-backup/1 commitment"
    INFO_WRAP     = "partiduo-backup/1 wrap"
    INFO_SERVERID = "partiduo-backup/1 server-key-id"

    # --- Primitives ------------------------------------------------------------

    def self.random_key : Bytes
      Random::Secure.random_bytes(KEY_SIZE)
    end

    def self.hmac(key : Bytes, data : String | Bytes) : Bytes
      OpenSSL::HMAC.digest(:sha256, key, data)
    end

    # HKDF-SHA256 (RFC 5869) pour une sortie de 32 octets : un seul bloc.
    def self.hkdf(ikm : Bytes, salt : Bytes, info : String) : Bytes
      prk = hmac(salt, ikm)
      block = IO::Memory.new
      block.write(info.to_slice)
      block.write_byte(1_u8)
      hmac(prk, block.to_slice)
    end

    # Engagement sur la clé de données : permet de reconnaître la bonne clé
    # (et de refuser une mauvaise) sans rien révéler d'elle.
    def self.commitment(data_key : Bytes) : Bytes
      hmac(data_key, INFO_COMMIT)
    end

    def self.sha256(data : Bytes) : Bytes
      Digest::SHA256.digest(data)
    end

    def self.hex(bytes : Bytes) : String
      bytes.hexstring
    end

    def self.unhex(value : String) : Bytes?
      value.hexbytes? if value.size.even?
    end

    # Empreinte présentée à l'écran : 64 chiffres hexadécimaux par groupes de 4.
    def self.display_fingerprint(hex : String) : String
      hex.scan(/.{1,4}/).map(&.[0]).join(' ')
    end

    # Égalité en temps constant.
    def self.same?(a : Bytes, b : Bytes) : Bool
      return false unless a.size == b.size
      diff = 0_u8
      a.size.times { |index| diff |= a[index] ^ b[index] }
      diff == 0
    end

    # AES-256-GCM en un appel : rend le chiffré suivi de l'étiquette (16 octets).
    def self.gcm_seal(key : Bytes, nonce : Bytes, aad : Bytes, plain : Bytes) : Bytes
      Gcm.new(key).seal(nonce, aad, plain)
    end

    # Rend le clair, ou lève `Error` si l'étiquette ne correspond pas.
    def self.gcm_open(key : Bytes, nonce : Bytes, aad : Bytes, sealed : Bytes) : Bytes
      Gcm.new(key).open(nonce, aad, sealed)
    end

    # Contexte AES-256-GCM réutilisable (un par fichier).
    class Gcm
      def initialize(@key : Bytes)
        raise Error.new("clé AES-256 de #{@key.size} octets") unless @key.size == KEY_SIZE
        @ctx = LibCrypto.evp_cipher_ctx_new
      end

      def finalize
        LibCrypto.evp_cipher_ctx_free(@ctx)
      end

      def seal(nonce : Bytes, aad : Bytes, plain : Bytes) : Bytes
        output = Bytes.new(plain.size + TAG_SIZE)
        init(nonce, 1)
        feed_aad(aad)
        length = 0
        unless plain.empty?
          check LibCrypto.evp_cipherupdate(@ctx, output.to_unsafe, pointerof(length), plain.to_unsafe, plain.size)
        end
        final = 0
        check LibCrypto.evp_cipherfinal_ex(@ctx, output.to_unsafe + length, pointerof(final))
        check LibCrypto.evp_cipher_ctx_ctrl(@ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (output.to_unsafe + plain.size).as(Void*))
        output
      end

      def open(nonce : Bytes, aad : Bytes, sealed : Bytes) : Bytes
        raise Error.new("segment trop court") if sealed.size < TAG_SIZE
        body = sealed[0, sealed.size - TAG_SIZE]
        tag = sealed[sealed.size - TAG_SIZE, TAG_SIZE].dup
        output = Bytes.new(body.size)
        init(nonce, 0)
        feed_aad(aad)
        length = 0
        unless body.empty?
          check LibCrypto.evp_cipherupdate(@ctx, output.to_unsafe, pointerof(length), body.to_unsafe, body.size)
        end
        check LibCrypto.evp_cipher_ctx_ctrl(@ctx, LibCrypto::EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.to_unsafe.as(Void*))
        final = 0
        if LibCrypto.evp_cipherfinal_ex(@ctx, output.to_unsafe + length, pointerof(final)) != 1
          LibCrypto.pd_err_clear_error
          raise Error.new("enveloppe altérée : authentification refusée")
        end
        output
      end

      private def init(nonce : Bytes, encrypt : Int32) : Nil
        raise Error.new("nonce de #{nonce.size} octets") unless nonce.size == NONCE_SIZE
        check LibCrypto.evp_cipherinit_ex(@ctx, LibCrypto.evp_aes_256_gcm, nil, nil, nil, encrypt)
        check LibCrypto.evp_cipher_ctx_ctrl(@ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, Pointer(Void).null)
        check LibCrypto.evp_cipherinit_ex(@ctx, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), nil, @key.to_unsafe, nonce.to_unsafe, encrypt)
      end

      private def feed_aad(aad : Bytes) : Nil
        return if aad.empty?
        length = 0
        check LibCrypto.evp_cipherupdate(@ctx, Pointer(UInt8).null, pointerof(length), aad.to_unsafe, aad.size)
      end

      private def check(code : Int32) : Nil
        return if code == 1
        LibCrypto.pd_err_clear_error
        raise Error.new("AES-256-GCM : erreur d'OpenSSL")
      end
    end

    # --- Clés --------------------------------------------------------------------

    # Clé du serveur : 32 octets aléatoires, dans l'état de l'exécutant
    # (jamais sous le répertoire des sauvegardes ni dans l'administration).
    # Protège les copies hors site ; le serveur restaure seul.
    class ServerKey
      getter key : Bytes

      def initialize(@key : Bytes)
        raise Error.new("clé du serveur de #{@key.size} octets (32 attendus)") unless @key.size == KEY_SIZE
      end

      # Fichier : 64 chiffres hexadécimaux (copie hors ligne aisée).
      def self.load(path : String) : ServerKey
        bytes = BackupCrypto.unhex(File.read(path).strip) || raise Error.new("clé du serveur illisible : #{path}")
        new(bytes)
      end

      # Crée la clé si elle n'existe pas (fichier 0600, création exclusive).
      # Création exclusive : fichier temporaire puis lien physique, qui
      # échoue si la clé existe déjà (deux exécutants à la fois).
      def self.load_or_create(path : String) : {ServerKey, Bool}
        return {load(path), false} if File.exists?(path)
        Dir.mkdir_p(File.dirname(path), 0o700)
        key = BackupCrypto.random_key
        temporary = "#{path}.#{Random::Secure.hex(6)}.tmp"
        begin
          File.write(temporary, "#{key.hexstring}\n", perm: 0o600)
          File.link(temporary, path)
          {new(key), true}
        rescue File::AlreadyExistsError
          {load(path), false}
        ensure
          File.delete(temporary) if File.exists?(temporary)
        end
      end

      # Identifiant public de la clé (HMAC, ne révèle rien d'elle).
      def id : Bytes
        BackupCrypto.hmac(key, INFO_SERVERID)
      end

      def fingerprint : String
        id.hexstring
      end

      def wrap(data_key : Bytes) : Bytes
        nonce = Random::Secure.random_bytes(NONCE_SIZE)
        io = IO::Memory.new
        io.write(nonce)
        io.write(BackupCrypto.gcm_seal(key, nonce, INFO_WRAP.to_slice, data_key))
        io.to_slice
      end

      def unwrap(wrapped : Bytes) : Bytes
        raise Error.new("clé de données enveloppée illisible") unless wrapped.size == NONCE_SIZE + KEY_SIZE + TAG_SIZE
        BackupCrypto.gcm_open(key, wrapped[0, NONCE_SIZE], INFO_WRAP.to_slice, wrapped[NONCE_SIZE..])
      rescue ex : Error
        raise Error.new("mauvaise clé du serveur : #{ex.message}")
      end
    end

    # Rappel de mot de passe pour les PEM chiffrés : la phrase de passe est
    # passée par `u` (chaîne terminée par un zéro) ; vide : échec, jamais de
    # question posée sur le terminal.
    PASSWORD_CALLBACK = ->(buffer : UInt8*, size : Int32, _rwflag : Int32, data : Void*) : Int32 {
      return 0 if data.null?
      source = data.as(UInt8*)
      length = LibC.strlen(source).to_i32
      return 0 if length == 0 || length > size
      buffer.copy_from(source, length)
      length
    }

    # Clé publique RSA du cabinet (PEM « PUBLIC KEY », SubjectPublicKeyInfo),
    # 3072 bits au moins. Empreinte : SHA-256 du DER de la clé publique, la
    # même que `openssl pkey -pubin -outform DER | openssl dgst -sha256`.
    class PublicKey
      getter der : Bytes
      getter bits : Int32

      def initialize(pem : String)
        pkey = BackupCrypto.read_pem(pem, secret: false, passphrase: "")
        begin
          unless LibCrypto.pd_evp_pkey_get_base_id(pkey) == LibCrypto::PD_EVP_PKEY_RSA
            raise Error.new("clé publique refusée : RSA seulement")
          end
          @bits = LibCrypto.pd_evp_pkey_get_bits(pkey)
          raise Error.new("clé publique refusée : #{@bits} bits (#{MIN_RSA_BITS} au moins)") if @bits < MIN_RSA_BITS
          @der = BackupCrypto.spki_der(pkey)
          @pem = pem
        ensure
          LibCrypto.evp_pkey_free(pkey)
        end
      end

      def fingerprint : String
        BackupCrypto.sha256(der).hexstring
      end

      def id : Bytes
        BackupCrypto.sha256(der)
      end

      # PEM normalisé (lignes de 64 caractères), tel que conservé.
      def pem : String
        body = Base64.strict_encode(der).scan(/.{1,64}/).map(&.[0]).join('\n')
        "-----BEGIN PUBLIC KEY-----\n#{body}\n-----END PUBLIC KEY-----\n"
      end

      def wrap(data_key : Bytes) : Bytes
        pkey = BackupCrypto.read_pem(pem, secret: false, passphrase: "")
        BackupCrypto.rsa_oaep(pkey, data_key, encrypt: true)
      ensure
        LibCrypto.evp_pkey_free(pkey) if pkey
      end
    end

    # Clé privée du cabinet (PEM PKCS#8, chiffré ou non). Jamais sur le
    # serveur ni dans l'administration : sert à la commande
    # `partiduo-agent decrypt` sur le poste du cabinet et aux specs.
    class PrivateKey
      @pkey : LibCrypto::EvpPKey?

      def initialize(pem : String, passphrase : String = "")
        pkey = BackupCrypto.read_pem(pem, secret: true, passphrase: passphrase)
        unless LibCrypto.pd_evp_pkey_get_base_id(pkey) == LibCrypto::PD_EVP_PKEY_RSA
          LibCrypto.evp_pkey_free(pkey)
          raise Error.new("clé privée refusée : RSA seulement")
        end
        @pkey = pkey
      end

      def finalize
        @pkey.try { |pkey| LibCrypto.evp_pkey_free(pkey) }
      end

      private def pkey : LibCrypto::EvpPKey
        @pkey || raise Error.new("clé privée fermée")
      end

      def id : Bytes
        BackupCrypto.sha256(BackupCrypto.spki_der(pkey))
      end

      def fingerprint : String
        id.hexstring
      end

      def unwrap(wrapped : Bytes) : Bytes
        BackupCrypto.rsa_oaep(pkey, wrapped, encrypt: false)
      rescue ex : Error
        raise Error.new("mauvaise clé du cabinet : #{ex.message}")
      end
    end

    protected def self.read_pem(pem : String, secret : Bool, passphrase : String) : LibCrypto::EvpPKey
      raise Error.new("clé PEM trop longue") if pem.bytesize > 64 * 1024
      bio = LibCrypto.pd_bio_new_mem_buf(pem.to_unsafe.as(Void*), pem.bytesize)
      raise Error.new("clé PEM illisible") if bio.null?
      begin
        phrase = passphrase.empty? ? Pointer(Void).null : passphrase.to_unsafe.as(Void*)
        pkey = if secret
                 LibCrypto.pd_pem_read_bio_private_key(bio, nil, PASSWORD_CALLBACK, phrase)
               else
                 LibCrypto.pd_pem_read_bio_pubkey(bio, nil, PASSWORD_CALLBACK, phrase)
               end
        if pkey.null?
          LibCrypto.pd_err_clear_error
          raise Error.new(secret ? "clé privée illisible (PEM PKCS#8 attendu ; phrase de passe exacte si elle est chiffrée)" : "clé publique illisible (PEM « PUBLIC KEY » attendu)")
        end
        pkey
      ensure
        LibCrypto.BIO_free(bio)
      end
    end

    protected def self.spki_der(pkey : LibCrypto::EvpPKey) : Bytes
      length = LibCrypto.pd_i2d_pubkey(pkey, nil)
      raise Error.new("clé publique illisible") if length <= 0
      der = Bytes.new(length)
      cursor = der.to_unsafe
      LibCrypto.pd_i2d_pubkey(pkey, pointerof(cursor))
      der
    end

    protected def self.rsa_oaep(pkey : LibCrypto::EvpPKey, input : Bytes, encrypt : Bool) : Bytes
      ctx = LibCrypto.evp_pkey_ctx_new(pkey, nil)
      raise Error.new("RSA-OAEP : contexte") if ctx.null?
      begin
        ok = encrypt ? LibCrypto.pd_evp_pkey_encrypt_init(ctx) : LibCrypto.pd_evp_pkey_decrypt_init(ctx)
        ok = ok == 1 && LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_padding_mode", "oaep") > 0 &&
             LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_oaep_md", "sha256") > 0 &&
             LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_mgf1_md", "sha256") > 0
        raise Error.new("RSA-OAEP : paramètres refusés") unless ok
        length = LibC::SizeT.new(0)
        call = ->(target : UInt8*, size : LibC::SizeT*) {
          encrypt ? LibCrypto.pd_evp_pkey_encrypt(ctx, target, size, input.to_unsafe, input.size) : LibCrypto.pd_evp_pkey_decrypt(ctx, target, size, input.to_unsafe, input.size)
        }
        raise Error.new("RSA-OAEP : taille") unless call.call(Pointer(UInt8).null, pointerof(length)) == 1
        output = Bytes.new(length)
        raise Error.new("RSA-OAEP : #{encrypt ? "chiffrement" : "déchiffrement"} refusé") unless call.call(output.to_unsafe, pointerof(length)) == 1
        output[0, length]
      ensure
        LibCrypto.pd_err_clear_error
        LibCrypto.evp_pkey_ctx_free(ctx)
      end
    end

    # --- En-tête -----------------------------------------------------------------

    # En-tête d'un fichier chiffré (format 1), entièrement authentifié comme
    # données associées de chaque segment.
    record Header, mode : UInt8, chunk_size : Int32, key_id : Bytes, salt : Bytes, commitment : Bytes,
      wrapped : Bytes do
      def to_slice : Bytes
        io = IO::Memory.new
        io.write(MAGIC)
        io.write_byte(VERSION)
        io.write_byte(mode)
        io.write_bytes(chunk_size.to_u32, IO::ByteFormat::BigEndian)
        io.write(key_id)
        io.write(salt)
        io.write(commitment)
        io.write_bytes(wrapped.size.to_u16, IO::ByteFormat::BigEndian)
        io.write(wrapped)
        io.to_slice
      end

      def size : Int32
        HEADER_FIXED + wrapped.size
      end

      def mode_name : String
        mode == SERVER ? "server" : "cabinet"
      end

      def self.read(io : IO) : Header
        fixed = Bytes.new(HEADER_FIXED)
        raise Error.new("enveloppe illisible : en-tête tronqué") unless BackupCrypto.read_full(io, fixed) == HEADER_FIXED
        raise Error.new("enveloppe illisible : ce n'est pas une sauvegarde chiffrée de Partiduo") unless fixed[0, 7] == MAGIC
        raise Error.new("enveloppe illisible : format #{fixed[7]} inconnu") unless fixed[7] == VERSION
        mode = fixed[8]
        raise Error.new("enveloppe illisible : mode #{mode} inconnu") unless mode == SERVER || mode == CABINET
        chunk = IO::ByteFormat::BigEndian.decode(UInt32, fixed[9, 4]).to_i64
        raise Error.new("enveloppe illisible : segments de #{chunk} octets") unless (1024..MAX_CHUNK).includes?(chunk)
        length = IO::ByteFormat::BigEndian.decode(UInt16, fixed[109, 2]).to_i
        raise Error.new("enveloppe illisible : clé enveloppée de #{length} octets") unless (1..MAX_WRAPPED).includes?(length)
        wrapped = Bytes.new(length)
        raise Error.new("enveloppe illisible : en-tête tronqué") unless BackupCrypto.read_full(io, wrapped) == length
        new(mode, chunk.to_i32, fixed[13, 32].dup, fixed[45, 32].dup, fixed[77, 32].dup, wrapped)
      end
    end

    # Lit jusqu'à remplir `buffer` ou atteindre la fin ; rend le nombre lu.
    def self.read_full(io : IO, buffer : Bytes) : Int32
      total = 0
      while total < buffer.size
        count = io.read(buffer[total..])
        break if count == 0
        total += count
      end
      total
    end

    def self.nonce(index : UInt64, final : Bool) : Bytes
      nonce = Bytes.new(NONCE_SIZE)
      value = index
      10.downto(3) do |position|
        nonce[position] = (value & 0xff).to_u8
        value >>= 8
      end
      nonce[11] = final ? 1_u8 : 0_u8
      nonce
    end

    # --- Scellement d'une sauvegarde --------------------------------------------

    # Clé de données d'une sauvegarde et son enveloppe : chaque fichier de la
    # sauvegarde (base, pièces jointes) en reçoit une copie de l'en-tête, avec
    # son propre sel.
    class Sealer
      getter mode : UInt8
      getter key_id : Bytes
      getter wrapped : Bytes
      getter data_key : Bytes

      def initialize(@mode : UInt8, @key_id : Bytes, @wrapped : Bytes, @data_key : Bytes)
      end

      def self.server(key : ServerKey, data_key : Bytes = BackupCrypto.random_key) : Sealer
        new(SERVER, key.id, key.wrap(data_key), data_key)
      end

      def self.cabinet(key : PublicKey, data_key : Bytes = BackupCrypto.random_key) : Sealer
        new(CABINET, key.id, key.wrap(data_key), data_key)
      end

      def commitment : Bytes
        BackupCrypto.commitment(data_key)
      end

      def mode_name : String
        mode == SERVER ? "server" : "cabinet"
      end

      def header(chunk_size : Int32 = CHUNK_SIZE) : Header
        Header.new(mode, chunk_size, key_id, Random::Secure.random_bytes(32), commitment, wrapped)
      end

      def writer(io : IO, chunk_size : Int32 = CHUNK_SIZE) : Writer
        Writer.new(io, header(chunk_size), data_key)
      end

      # Description transmise à l'administration (jamais la clé de données).
      def describe : Hash(String, String | Int32)
        {"format" => VERSION.to_i32, "mode" => mode_name, "key_fingerprint" => key_id.hexstring,
         "commitment" => commitment.hexstring, "wrapped_key" => Base64.strict_encode(wrapped)}
      end
    end

    # Flux chiffrant : `write` accumule, chaque segment plein part chiffré ;
    # `close` écrit le dernier segment (toujours plus court qu'un segment
    # plein, vide au besoin) et ferme le flux sous-jacent.
    class Writer < IO
      getter header : Header
      getter plain_bytes = 0_i64

      def initialize(@io : IO, @header : Header, data_key : Bytes)
        @aad = @header.to_slice
        @gcm = Gcm.new(BackupCrypto.hkdf(data_key, @header.salt, INFO_DATA))
        @buffer = Bytes.new(@header.chunk_size)
        @filled = 0
        @index = 0_u64
        @finished = false
        @io.write(@aad)
      end

      def read(slice : Bytes) : Int32
        raise IO::Error.new("flux chiffrant en écriture seule")
      end

      def write(slice : Bytes) : Nil
        raise IO::Error.new("flux chiffrant déjà fermé") if @finished
        offset = 0
        while offset < slice.size
          # Segment plein et d'autres octets à venir : il n'est pas le dernier.
          emit(false) if @filled == @buffer.size
          count = Math.min(@buffer.size - @filled, slice.size - offset)
          @buffer[@filled, count].copy_from(slice[offset, count])
          @filled += count
          offset += count
        end
        @plain_bytes += slice.size
      end

      def close : Nil
        return if @finished
        emit(false) if @filled == @buffer.size
        emit(true)
        @finished = true
        @io.flush
        @io.close
      end

      def closed? : Bool
        @finished
      end

      private def emit(final : Bool) : Nil
        @io.write(@gcm.seal(BackupCrypto.nonce(@index, final), @aad, @buffer[0, @filled]))
        @index += 1
        @filled = 0
      end
    end

    # Flux déchiffrant (`BackupCrypto::Error` explicite : dans une sous-classe
    # d'`IO`, `Error` serait `IO::Error`) : chaque segment est authentifié avant d'être rendu ;
    # une enveloppe tronquée, prolongée ou réordonnée lève `Error`.
    class Reader < IO
      getter header : Header

      def initialize(@io : IO, @header : Header, data_key : Bytes)
        unless BackupCrypto.same?(BackupCrypto.commitment(data_key), @header.commitment)
          raise BackupCrypto::Error.new("mauvaise clé de données pour cette sauvegarde")
        end
        @aad = @header.to_slice
        @gcm = Gcm.new(BackupCrypto.hkdf(data_key, @header.salt, INFO_DATA))
        @segment = Bytes.new(@header.chunk_size + TAG_SIZE)
        @plain = Bytes.empty
        @position = 0
        @index = 0_u64
        @done = false
      end

      def read(slice : Bytes) : Int32
        return 0 if slice.empty?
        while @position >= @plain.size
          return 0 if @done
          next_segment
        end
        count = Math.min(slice.size, @plain.size - @position)
        slice.copy_from(@plain[@position, count])
        @position += count
        count
      end

      def write(slice : Bytes) : Nil
        raise IO::Error.new("flux déchiffrant en lecture seule")
      end

      def close : Nil
        @io.close
      end

      private def next_segment : Nil
        count = BackupCrypto.read_full(@io, @segment)
        raise BackupCrypto::Error.new("enveloppe tronquée : segment #{@index} manquant") if count == 0
        raise BackupCrypto::Error.new("enveloppe tronquée : segment #{@index} incomplet") if count < TAG_SIZE
        final = count < @segment.size
        @plain = @gcm.open(BackupCrypto.nonce(@index, final), @aad, @segment[0, count])
        @position = 0
        @index += 1
        if final
          @done = true
          raise BackupCrypto::Error.new("enveloppe altérée : octets après le dernier segment") unless @io.read(Bytes.new(1)) == 0
        end
      end
    end

    # --- Fichiers ---------------------------------------------------------------

    def self.sealed_path?(path : String) : Bool
      path.ends_with?(EXTENSION)
    end

    def self.read_header(path : String) : Header
      File.open(path, "rb") { |file| Header.read(file) }
    rescue ex : File::Error
      raise Error.new("sauvegarde illisible : #{ex.message}")
    end

    # Vérification *sans clé* : en-tête bien formé, clé attendue (empreinte),
    # engagement attendu, découpage en segments cohérent jusqu'au dernier.
    # N'authentifie pas le contenu : seule la clé le peut.
    def self.check_structure(path : String, key_fingerprint : String = "", commitment : String = "") : Header
      header = read_header(path)
      if !key_fingerprint.empty? && header.key_id.hexstring != key_fingerprint
        raise Error.new("enveloppe d'une autre clé (#{header.key_id.hexstring[0, 16]}…, attendue #{key_fingerprint[0, 16]}…)")
      end
      if !commitment.empty? && header.commitment.hexstring != commitment
        raise Error.new("enveloppe altérée : engagement de la clé de données inattendu")
      end
      body = File.size(path).to_i64 - header.size
      segment = header.chunk_size.to_i64 + TAG_SIZE
      raise Error.new("enveloppe tronquée : aucun segment") if body < TAG_SIZE
      raise Error.new("enveloppe tronquée : dernier segment manquant") if body % segment < TAG_SIZE
      header
    end

    # Déchiffre tout le fichier sans rien garder : authentifie chaque segment.
    def self.verify(path : String, data_key : Bytes) : Int64
      total = 0_i64
      File.open(path, "rb") do |file|
        reader = Reader.new(file, Header.read(file), data_key)
        buffer = Bytes.new(CHUNK_SIZE)
        while (count = reader.read(buffer)) > 0
          total += count
        end
      end
      total
    end
  end
end
