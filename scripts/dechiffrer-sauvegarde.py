#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Déchiffre une sauvegarde chiffrée de Partiduo (format 1) hors de Partiduo.

Implémentation indépendante du format décrit dans le README de
partiduo-admin (« Format de l'enveloppe ») : elle ne partage aucun code avec
l'exécutant et sert aussi à le vérifier. Dépendance : le paquet Python
`cryptography` (OpenSSL).

  # Clé du cabinet (PEM PKCS#8, phrase de passe demandée si elle est chiffrée)
  dechiffrer-sauvegarde.py --private-key cabinet-prive.pem backup-….dump.enc backup.dump

  # Clé de données obtenue par `openssl pkeyutl` (voir le README)
  dechiffrer-sauvegarde.py --wrapped-key-out cle.bin backup-….dump.enc
  dechiffrer-sauvegarde.py --data-key-file dek.bin backup-….dump.enc backup.dump

  # Clé du serveur (64 chiffres hexadécimaux)
  dechiffrer-sauvegarde.py --server-key backup-server.key backup-….dump.enc backup.dump
"""

import argparse
import getpass
import hashlib
import hmac
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PDUOBAK"
HEADER_FIXED = 111
TAG = 16


def fail(message):
    sys.stderr.write("dechiffrer-sauvegarde : %s\n" % message)
    sys.exit(1)


def read_header(stream):
    fixed = stream.read(HEADER_FIXED)
    if len(fixed) != HEADER_FIXED or fixed[:7] != MAGIC:
        fail("ce n'est pas une sauvegarde chiffrée de Partiduo")
    if fixed[7] != 1:
        fail("format %d inconnu" % fixed[7])
    mode = fixed[8]
    (chunk,) = struct.unpack(">I", fixed[9:13])
    key_id, salt, commitment = fixed[13:45], fixed[45:77], fixed[77:109]
    (length,) = struct.unpack(">H", fixed[109:111])
    wrapped = stream.read(length)
    if len(wrapped) != length or mode not in (1, 2) or not 1024 <= chunk <= 16 * 1024 * 1024:
        fail("en-tête illisible")
    return {"raw": fixed + wrapped, "mode": mode, "chunk": chunk, "key_id": key_id, "salt": salt,
            "commitment": commitment, "wrapped": wrapped}


def data_key(header, args):
    if args.data_key_file:
        with open(args.data_key_file, "rb") as handle:
            return handle.read()
    if args.server_key:
        if header["mode"] != 1:
            fail("sauvegarde chiffrée par la clé du cabinet, pas par celle du serveur")
        with open(args.server_key) as handle:
            key = bytes.fromhex(handle.read().strip())
        wrapped = header["wrapped"]
        return AESGCM(key).decrypt(wrapped[:12], wrapped[12:], b"partiduo-backup/1 wrap")
    if args.private_key:
        if header["mode"] != 2:
            fail("sauvegarde chiffrée par la clé du serveur, pas par celle du cabinet")
        with open(args.private_key, "rb") as handle:
            pem = handle.read()
        password = None
        if b"ENCRYPTED" in pem:
            password = getpass.getpass("Phrase de passe de la clé du cabinet : ").encode()
        key = serialization.load_pem_private_key(pem, password=password)
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        if hashlib.sha256(spki).digest() != header["key_id"]:
            fail("cette clé n'est pas celle de la sauvegarde (empreinte %s)" % header["key_id"].hex())
        return key.decrypt(header["wrapped"], padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
    fail("indiquez --private-key, --server-key ou --data-key-file")


def decrypt(stream, output, header, dek):
    commitment = hmac.new(dek, b"partiduo-backup/1 commitment", hashlib.sha256).digest()
    if not hmac.compare_digest(commitment, header["commitment"]):
        fail("mauvaise clé de données")
    file_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=header["salt"],
                    info=b"partiduo-backup/1 data").derive(dek)
    aead = AESGCM(file_key)
    segment = header["chunk"] + TAG
    index = 0
    while True:
        data = stream.read(segment)
        if len(data) < TAG:
            fail("enveloppe tronquée (segment %d)" % index)
        final = len(data) < segment
        nonce = index.to_bytes(11, "big") + (b"\x01" if final else b"\x00")
        output.write(aead.decrypt(nonce, data, header["raw"]))
        index += 1
        if final:
            if stream.read(1):
                fail("octets après le dernier segment")
            return


def main():
    parser = argparse.ArgumentParser(description="Déchiffre une sauvegarde chiffrée de Partiduo (format 1).")
    parser.add_argument("--private-key", help="clé privée du cabinet (PEM PKCS#8)")
    parser.add_argument("--server-key", help="clé du serveur (fichier de 64 chiffres hexadécimaux)")
    parser.add_argument("--data-key-file", help="clé de données en clair (32 octets, sortie d'openssl pkeyutl)")
    parser.add_argument("--wrapped-key-out", help="écrit la clé de données enveloppée (pour openssl pkeyutl) et s'arrête")
    parser.add_argument("source")
    parser.add_argument("destination", nargs="?")
    args = parser.parse_args()
    with open(args.source, "rb") as stream:
        header = read_header(stream)
        if args.wrapped_key_out:
            with open(args.wrapped_key_out, "wb") as handle:
                handle.write(header["wrapped"])
            print("mode %s, empreinte de la clé %s" % ("serveur" if header["mode"] == 1 else "cabinet",
                                                      header["key_id"].hex()))
            return
        if not args.destination:
            fail("fichier de destination manquant")
        dek = data_key(header, args)
        try:
            with open(args.destination, "wb") as output:
                decrypt(stream, output, header, dek)
        except Exception as error:  # étiquette refusée : fichier altéré
            fail("enveloppe altérée ou mauvaise clé (%s)" % type(error).__name__)


if __name__ == "__main__":
    main()
