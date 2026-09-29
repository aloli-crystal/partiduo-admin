# SPDX-License-Identifier: AGPL-3.0-or-later

require "../spec_helper"

# Chiffrement des sauvegardes (D-CHF-001 à D-CHF-012) : enveloppe hybride
# AES-256-GCM, clé du serveur ou clé publique RSA-OAEP du cabinet, format 1.

private alias Crypto = PartiduoAdmin::BackupCrypto

private def seal(data : Bytes, sealer : Crypto::Sealer, chunk : Int32 = Crypto::CHUNK_SIZE) : Bytes
  io = IO::Memory.new
  writer = sealer.writer(io, chunk)
  # Écritures de tailles irrégulières, comme un tube.
  offset = 0
  step = 1
  while offset < data.size
    count = Math.min(step, data.size - offset)
    writer.write(data[offset, count])
    offset += count
    step = step * 3 % 7919 + 1
  end
  writer.close
  io.to_slice
end

private def unseal(sealed : Bytes, data_key : Bytes) : Bytes
  io = IO::Memory.new(sealed)
  header = Crypto::Header.read(io)
  Crypto::Reader.new(io, header, data_key).gets_to_end.to_slice
end

private def temp_file(bytes : Bytes) : String
  path = File.join(Dir.tempdir, "partiduo-chf-#{Random::Secure.hex(6)}.enc")
  File.write(path, bytes)
  path
end

describe PartiduoAdmin::BackupCrypto do
  it "chiffre et déchiffre en flux, quelle que soit la taille (segments pleins, dernier segment court ou vide)" do
    sealer = Crypto::Sealer.server(Crypto::ServerKey.new(Crypto.random_key))
    [0, 1, 1023, 1024, 1025, 3 * 1024, 5000].each do |size|
      data = Random.new(size).random_bytes(size)
      sealed = seal(data, sealer, 1024)
      unseal(sealed, sealer.data_key).should eq(data)
      segments = size // 1024 + 1
      header_size = Crypto::HEADER_FIXED + sealer.wrapped.size
      sealed.size.should eq(header_size + size + segments * Crypto::TAG_SIZE)
    end
  end

  it "chiffre un flux volumineux en mémoire bornée (segments de 64 Kio)" do
    sealer = Crypto::Sealer.server(Crypto::ServerKey.new(Crypto.random_key))
    path = File.join(Dir.tempdir, "partiduo-chf-gros-#{Random::Secure.hex(4)}.enc")
    digest = Digest::SHA256.new
    total = 24 * 1024 * 1024 + 12_345
    File.open(path, "wb") do |file|
      writer = sealer.writer(file)
      generator = Random.new(42)
      remaining = total
      while remaining > 0
        block = generator.random_bytes(Math.min(remaining, 1_000_003))
        digest.update(block)
        writer.write(block)
        remaining -= block.size
      end
      writer.close
      writer.plain_bytes.should eq(total)
    end
    expected = digest.hexfinal
    check = Digest::SHA256.new
    read = 0_i64
    File.open(path, "rb") do |file|
      reader = Crypto::Reader.new(file, Crypto::Header.read(file), sealer.data_key)
      buffer = Bytes.new(100_000)
      while (count = reader.read(buffer)) > 0
        check.update(buffer[0, count])
        read += count
      end
    end
    read.should eq(total)
    check.hexfinal.should eq(expected)
    Crypto.verify(path, sealer.data_key).should eq(total)
    Crypto.check_structure(path).mode.should eq(Crypto::SERVER)
  ensure
    File.delete(path) if path && File.exists?(path)
  end

  it "écrit l'en-tête documenté du format 1" do
    key = Crypto::ServerKey.new(Crypto.random_key)
    sealer = Crypto::Sealer.server(key)
    sealed = seal("bonjour".to_slice, sealer)
    String.new(sealed[0, 7]).should eq("PDUOBAK")
    sealed[7].should eq(1)
    sealed[8].should eq(Crypto::SERVER)
    IO::ByteFormat::BigEndian.decode(UInt32, sealed[9, 4]).should eq(65_536)
    sealed[13, 32].should eq(key.id)
    sealed[77, 32].should eq(Crypto.commitment(sealer.data_key))
    IO::ByteFormat::BigEndian.decode(UInt16, sealed[109, 2]).should eq(60)
    # Clé de fichier : HKDF-SHA256 (clé de données, sel de l'en-tête).
    header = Crypto::Header.read(IO::Memory.new(sealed))
    file_key = Crypto.hkdf(sealer.data_key, header.salt, "partiduo-backup/1 data")
    segment = sealed[header.size..]
    Crypto.gcm_open(file_key, Crypto.nonce(0_u64, true), sealed[0, header.size], segment).should eq("bonjour".to_slice)
    # Chaque fichier d'une sauvegarde a son propre sel.
    seal("x".to_slice, sealer)[45, 32].should_not eq(sealed[45, 32])
  end

  it "vérifie HKDF-SHA256 sur le vecteur de test 1 de la RFC 5869 (premier bloc)" do
    ikm = Bytes.new(22, 0x0b_u8)
    salt = "000102030405060708090a0b0c".hexbytes
    info = String.new("f0f1f2f3f4f5f6f7f8f9".hexbytes)
    Crypto.hkdf(ikm, salt, info).hexstring.should eq("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
  end

  it "refuse une mauvaise clé de données, une autre clé du serveur, une autre clé du cabinet" do
    server = Crypto::ServerKey.new(Crypto.random_key)
    sealer = Crypto::Sealer.server(server)
    sealed = seal("comptabilité".to_slice, sealer)
    expect_raises(Crypto::Error, /mauvaise clé de données/) { unseal(sealed, Crypto.random_key) }
    expect_raises(Crypto::Error, /mauvaise clé du serveur/) do
      Crypto::ServerKey.new(Crypto.random_key).unwrap(sealer.wrapped)
    end

    a = AdminSpec::Keys.pair("a")
    b = AdminSpec::Keys.pair("b")
    cabinet = Crypto::Sealer.cabinet(Crypto::PublicKey.new(a.public_pem))
    right = Crypto::PrivateKey.new(a.private_pem, AdminSpec::Keys::PASSPHRASE)
    right.unwrap(cabinet.wrapped).should eq(cabinet.data_key)
    wrong = Crypto::PrivateKey.new(b.private_pem, AdminSpec::Keys::PASSPHRASE)
    expect_raises(Crypto::Error, /mauvaise clé du cabinet/) { wrong.unwrap(cabinet.wrapped) }
    expect_raises(Crypto::Error, /phrase de passe/) { Crypto::PrivateKey.new(a.private_pem, "autre phrase") }
    expect_raises(Crypto::Error, /phrase de passe/) { Crypto::PrivateKey.new(a.private_pem, "") }
  end

  it "détecte toute falsification : octet du contenu, de l'en-tête, troncature, ajout, segments échangés" do
    sealer = Crypto::Sealer.server(Crypto::ServerKey.new(Crypto.random_key))
    data = Random.new(7).random_bytes(4000)
    sealed = seal(data, sealer, 1024)
    header_size = Crypto::HEADER_FIXED + sealer.wrapped.size
    segment = 1024 + Crypto::TAG_SIZE

    flipped = sealed.dup
    flipped[header_size + 1500] ^= 0x01
    expect_raises(Crypto::Error, /altérée/) { unseal(flipped, sealer.data_key) }

    salted = sealed.dup
    salted[50] ^= 0x80
    expect_raises(Crypto::Error, /altérée/) { unseal(salted, sealer.data_key) }

    chunked = sealed.dup
    chunked[12] ^= 0x01 # taille des segments annoncée
    expect_raises(Crypto::Error) { unseal(chunked, sealer.data_key) }

    boundary = sealed[0, header_size + 2 * segment]
    expect_raises(Crypto::Error, /tronquée/) { unseal(boundary, sealer.data_key) }
    middle = sealed[0, sealed.size - 10]
    expect_raises(Crypto::Error) { unseal(middle, sealer.data_key) }
    expect_raises(Crypto::Error, /tronquée|illisible/) { unseal(sealed[0, header_size], sealer.data_key) }

    extended = IO::Memory.new
    extended.write(sealed)
    extended.write("x".to_slice)
    expect_raises(Crypto::Error) { unseal(extended.to_slice, sealer.data_key) }

    swapped = sealed.dup
    first = sealed[header_size, segment].dup
    swapped[header_size, segment].copy_from(sealed[header_size + segment, segment])
    swapped[header_size + segment, segment].copy_from(first)
    expect_raises(Crypto::Error, /altérée/) { unseal(swapped, sealer.data_key) }

    # Un fichier d'une autre sauvegarde n'est pas pris pour celui-ci.
    other = seal(data, Crypto::Sealer.server(Crypto::ServerKey.new(Crypto.random_key)), 1024)
    expect_raises(Crypto::Error, /mauvaise clé/) { unseal(other, sealer.data_key) }
  end

  it "vérifie l'enveloppe sans clé : structure, clé attendue, engagement, découpage" do
    a = AdminSpec::Keys.pair("a")
    public_key = Crypto::PublicKey.new(a.public_pem)
    sealer = Crypto::Sealer.cabinet(public_key)
    sealed = seal(Random.new(3).random_bytes(70_000), sealer)
    path = temp_file(sealed)
    header = Crypto.check_structure(path, public_key.fingerprint, sealer.commitment.hexstring)
    header.mode.should eq(Crypto::CABINET)
    header.wrapped.size.should eq(384)
    expect_raises(Crypto::Error, /autre clé/) { Crypto.check_structure(path, "00" * 32) }
    expect_raises(Crypto::Error, /engagement/) { Crypto.check_structure(path, public_key.fingerprint, "11" * 32) }
    # Sans clé, une troncature se voit au découpage (segment plein en dernier,
    # reste trop court) ; dans le dernier segment, seule la clé la voit.
    first_segment = header.size + Crypto::CHUNK_SIZE + Crypto::TAG_SIZE
    File.write(path, sealed[0, first_segment])
    expect_raises(Crypto::Error, /tronquée/) { Crypto.check_structure(path) }
    File.write(path, sealed[0, first_segment + 5])
    expect_raises(Crypto::Error, /tronquée/) { Crypto.check_structure(path) }
    File.write(path, "pas une sauvegarde")
    expect_raises(Crypto::Error, /illisible/) { Crypto.check_structure(path) }
  ensure
    File.delete(path) if path && File.exists?(path)
  end

  it "n'accepte que des clés publiques RSA de 3072 bits au moins, empreinte identique à celle d'openssl" do
    a = AdminSpec::Keys.pair("a")
    key = Crypto::PublicKey.new(a.public_pem)
    key.bits.should eq(3072)
    der = AdminSpec::Keys.openssl(["pkey", "-pubin", "-in", a.public_path, "-outform", "DER"])
    key.fingerprint.should eq(Digest::SHA256.hexdigest(der.to_slice))
    Crypto::PrivateKey.new(a.private_pem, AdminSpec::Keys::PASSPHRASE).fingerprint.should eq(key.fingerprint)
    Crypto.display_fingerprint(key.fingerprint).split(' ').size.should eq(16)

    small = AdminSpec::Keys.pair("petite", 2048)
    expect_raises(Crypto::Error, /2048 bits/) { Crypto::PublicKey.new(small.public_pem) }
    expect_raises(Crypto::Error, /illisible/) { Crypto::PublicKey.new("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n") }
    expect_raises(Crypto::Error, /illisible/) { Crypto::PublicKey.new(a.private_pem) }
    ec = AdminSpec::Keys.openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
    ec_public = AdminSpec::Keys.openssl(["pkey", "-pubout"], IO::Memory.new(ec))
    expect_raises(Crypto::Error, /RSA seulement/) { Crypto::PublicKey.new(ec_public) }
  end

  it "se déchiffre hors de Partiduo : openssl pkeyutl pour la clé de données, script Python indépendant pour le contenu" do
    python = Process.find_executable("python3") || ""
    probe = !python.empty? && Process.run(python, ["-c", "import cryptography"]).success?
    pending!("python3 et le paquet cryptography sont requis") unless probe
    a = AdminSpec::Keys.pair("a")
    sealer = Crypto::Sealer.cabinet(Crypto::PublicKey.new(a.public_pem))
    data = Random.new(11).random_bytes(200_000)
    path = temp_file(seal(data, sealer))
    script = File.expand_path("../../scripts/dechiffrer-sauvegarde.py", __DIR__)
    wrapped = "#{path}.wrapped"
    data_key = "#{path}.dek"
    plain = "#{path}.plain"
    Process.run(python, [script, "--wrapped-key-out", wrapped, path]).success?.should be_true
    AdminSpec::Keys.openssl(["pkeyutl", "-decrypt", "-inkey", a.private_path, "-passin", "pass:#{AdminSpec::Keys::PASSPHRASE}",
                             "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                             "-pkeyopt", "rsa_mgf1_md:sha256", "-in", wrapped, "-out", data_key])
    File.read(data_key).to_slice.should eq(sealer.data_key)
    Process.run(python, [script, "--data-key-file", data_key, path, plain]).success?.should be_true
    File.read(plain).to_slice.should eq(data)
  ensure
    [path, wrapped, data_key, plain].each { |file| File.delete(file) if file && File.exists?(file) }
  end
end

describe PartiduoAgent::Tools do
  it "déchiffre une sauvegarde avec la clé privée du cabinet et affiche l'en-tête (commandes locales)" do
    a = AdminSpec::Keys.pair("a")
    sealer = Crypto::Sealer.cabinet(Crypto::PublicKey.new(a.public_pem))
    data = Random.new(5).random_bytes(150_000)
    path = temp_file(seal(data, sealer))
    passphrase = "#{path}.phrase"
    File.write(passphrase, AdminSpec::Keys::PASSPHRASE + "\n")
    output = IO::Memory.new
    error = IO::Memory.new
    PartiduoAgent::Tools.run(["inspect", path], output, error).should eq(0)
    output.to_s.should contain("clé du cabinet")
    output.to_s.should contain(sealer.key_id.hexstring)
    PartiduoAgent::Tools.run(["decrypt", "--private-key", a.private_path, "--passphrase-file", passphrase,
                              path, "#{path}.plain"], output, error).should eq(0)
    File.read("#{path}.plain").to_slice.should eq(data)
    b = AdminSpec::Keys.pair("b")
    PartiduoAgent::Tools.run(["decrypt", "--private-key", b.private_path, "--passphrase-file", passphrase,
                              path, "#{path}.autre"], output, error).should eq(1)
    error.to_s.should contain("n'est pas celle de la sauvegarde")
    File.exists?("#{path}.autre").should be_false
  ensure
    [path, passphrase, "#{path}.plain"].each { |file| File.delete(file) if file && File.exists?(file) }
  end

  it "crée la clé du serveur une seule fois (0600) et affiche son empreinte" do
    directory = File.join(Dir.tempdir, "partiduo-chf-state-#{Random::Secure.hex(4)}")
    output = IO::Memory.new
    PartiduoAgent::Tools.run(["server-key", "--state-dir", directory], output).should eq(0)
    output.to_s.should contain("clé créée")
    path = File.join(directory, "backup-server.key")
    (File.info(path).permissions.value & 0o077).should eq(0)
    first = Crypto::ServerKey.load(path).fingerprint
    PartiduoAgent::Tools.run(["server-key", "--state-dir", directory], output).should eq(0)
    output.to_s.should contain("clé existante")
    Crypto::ServerKey.load(path).fingerprint.should eq(first)
    output.to_s.should contain(first)
  end
end
