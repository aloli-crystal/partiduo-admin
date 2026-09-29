/* SPDX-License-Identifier: AGPL-3.0-or-later
   Clé du cabinet pour le chiffrement des sauvegardes (DECISIONS D-CHF-002,
   D-CHF-005), dans le navigateur de l'admin du cabinet, par WebCrypto :

   * [data-pd-keygen] : produit une paire RSA-OAEP 3072 bits (SHA-256),
     télécharge la clé privée chiffrée par la phrase de passe (PKCS#8
     PBES2 : PBKDF2-HMAC-SHA256, AES-256-CBC — lisible par `openssl pkey`),
     place la clé publique (PEM) dans le formulaire de dépôt ;
   * [data-pd-pubkey] : affiche l'empreinte SHA-256 de la clé publique
     collée (la même que `openssl pkey -pubin -outform DER | openssl dgst
     -sha256`) ;
   * [data-pd-unlock] : lit la clé privée (fichier ou texte, chiffrée ou
     non), vérifie qu'elle est celle de la sauvegarde, déchiffre la clé de
     données de cette sauvegarde et n'envoie qu'elle (champ `data_key`).

   La clé privée et la phrase de passe ne quittent jamais la page : leurs
   champs n'ont pas d'attribut `name` et sont vidés avant l'envoi. */
(function () {
  "use strict";

  var subtle = window.crypto && window.crypto.subtle;
  var PBKDF2_ITERATIONS = 600000;
  var RSA = { name: "RSA-OAEP", hash: "SHA-256" };

  // --- Octets, base64, PEM ----------------------------------------------------

  function toBase64(bytes) {
    var raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw);
  }

  function fromBase64(text) {
    var raw = atob(text.replace(/\s+/g, ""));
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }

  function toHex(bytes) {
    return Array.prototype.map.call(bytes, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }

  function grouped(hex) {
    return hex.match(/.{1,4}/g).join(" ");
  }

  function pem(label, bytes) {
    var body = toBase64(bytes).match(/.{1,64}/g).join("\n");
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
  }

  function unpem(text) {
    var match = /-----BEGIN ([A-Z ]+)-----([\s\S]+?)-----END \1-----/.exec(text || "");
    if (!match) return null;
    return { label: match[1], der: fromBase64(match[2]) };
  }

  // --- DER minimal (PKCS#8 chiffré, PBES2) ------------------------------------

  function concat(parts) {
    var size = parts.reduce(function (sum, part) { return sum + part.length; }, 0);
    var out = new Uint8Array(size);
    var offset = 0;
    parts.forEach(function (part) { out.set(part, offset); offset += part.length; });
    return out;
  }

  function tlv(tag, content) {
    var length = content.length;
    var header;
    if (length < 0x80) header = [tag, length];
    else if (length < 0x100) header = [tag, 0x81, length];
    else if (length < 0x10000) header = [tag, 0x82, length >> 8, length & 0xff];
    else header = [tag, 0x83, length >> 16, (length >> 8) & 0xff, length & 0xff];
    return concat([new Uint8Array(header), content]);
  }

  function seq() { return tlv(0x30, concat(Array.prototype.slice.call(arguments))); }
  function octets(bytes) { return tlv(0x04, bytes); }
  function oid(bytes) { return tlv(0x06, new Uint8Array(bytes)); }
  function integer(value) {
    var bytes = [];
    do { bytes.unshift(value & 0xff); value = Math.floor(value / 256); } while (value > 0);
    if (bytes[0] & 0x80) bytes.unshift(0);
    return tlv(0x02, new Uint8Array(bytes));
  }

  var OID = {
    pbes2: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d],
    pbkdf2: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c],
    hmacSha256: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
    hmacSha1: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
    aes256cbc: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
    aes128cbc: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]
  };

  function sameOid(bytes, expected) {
    if (!bytes || bytes.length !== expected.length) return false;
    for (var i = 0; i < expected.length; i++) if (bytes[i] !== expected[i]) return false;
    return true;
  }

  // Lecture d'un TLV : { tag, content, next }.
  function read(bytes, offset) {
    var tag = bytes[offset];
    var length = bytes[offset + 1];
    var start = offset + 2;
    if (length & 0x80) {
      var count = length & 0x7f;
      length = 0;
      for (var i = 0; i < count; i++) length = length * 256 + bytes[start + i];
      start += count;
    }
    if (start + length > bytes.length) throw new Error("DER");
    return { tag: tag, content: bytes.subarray(start, start + length), next: start + length };
  }

  function children(bytes) {
    var list = [];
    var offset = 0;
    while (offset < bytes.length) {
      var item = read(bytes, offset);
      list.push(item);
      offset = item.next;
    }
    return list;
  }

  function toInt(bytes) {
    var value = 0;
    for (var i = 0; i < bytes.length; i++) value = value * 256 + bytes[i];
    return value;
  }

  function pbkdf2Key(passphrase, salt, iterations, hash, bits) {
    return subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]).then(function (base) {
      return subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: iterations, hash: hash }, base,
        { name: "AES-CBC", length: bits }, false, ["encrypt", "decrypt"]);
    });
  }

  // PKCS#8 → EncryptedPrivateKeyInfo (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC).
  function encryptPkcs8(pkcs8, passphrase) {
    var salt = window.crypto.getRandomValues(new Uint8Array(16));
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    return pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS, "SHA-256", 256).then(function (key) {
      return subtle.encrypt({ name: "AES-CBC", iv: iv }, key, pkcs8);
    }).then(function (encrypted) {
      var params = seq(
        seq(oid(OID.pbkdf2), seq(octets(salt), integer(PBKDF2_ITERATIONS), seq(oid(OID.hmacSha256), tlv(0x05, new Uint8Array(0))))),
        seq(oid(OID.aes256cbc), octets(iv)));
      return seq(seq(oid(OID.pbes2), params), octets(new Uint8Array(encrypted)));
    });
  }

  // EncryptedPrivateKeyInfo → PKCS#8 (PBES2/PBKDF2, HMAC-SHA256 ou SHA-1,
  // AES-256-CBC ou AES-128-CBC : ce que produit `openssl genpkey -aes-256-cbc`).
  function decryptPkcs8(der, passphrase) {
    var top = children(read(der, 0).content);
    var algorithm = children(top[0].content);
    if (!sameOid(algorithm[0].content, OID.pbes2)) return Promise.reject(new Error("PBES2"));
    var params = children(algorithm[1].content);
    var kdf = children(params[0].content);
    if (!sameOid(kdf[0].content, OID.pbkdf2)) return Promise.reject(new Error("PBKDF2"));
    var kdfParams = children(kdf[1].content);
    var salt = kdfParams[0].content;
    var iterations = toInt(kdfParams[1].content);
    var hash = "SHA-1";
    kdfParams.slice(2).forEach(function (item) {
      if (item.tag === 0x30 && sameOid(children(item.content)[0].content, OID.hmacSha256)) hash = "SHA-256";
    });
    var scheme = children(params[1].content);
    var bits = sameOid(scheme[0].content, OID.aes256cbc) ? 256 : (sameOid(scheme[0].content, OID.aes128cbc) ? 128 : 0);
    if (!bits) return Promise.reject(new Error("AES"));
    var iv = scheme[1].content;
    return pbkdf2Key(passphrase, salt, iterations, hash, bits).then(function (key) {
      return subtle.decrypt({ name: "AES-CBC", iv: iv }, key, top[1].content);
    }).then(function (plain) { return new Uint8Array(plain); });
  }

  // Empreinte SHA-256 du SubjectPublicKeyInfo.
  function fingerprint(spki) {
    return subtle.digest("SHA-256", spki).then(function (digest) { return toHex(new Uint8Array(digest)); });
  }

  // Empreinte de la clé publique d'une clé privée (JWK : n, e).
  function privateFingerprint(privateKey) {
    return subtle.exportKey("jwk", privateKey).then(function (jwk) {
      return subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RSA-OAEP-256", ext: true }, RSA, true, ["encrypt"]);
    }).then(function (publicKey) {
      return subtle.exportKey("spki", publicKey);
    }).then(fingerprint);
  }

  function say(node, text, error) {
    if (!node) return;
    node.textContent = text || "";
    node.classList.toggle("is-error", !!error);
  }

  function download(name, text) {
    var link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
    link.download = name;
    document.body.appendChild(link);
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1000);
  }

  // --- Génération (page du cabinet) ------------------------------------------

  function setupKeygen(section) {
    var status = section.querySelector("[data-pd-keygen-status]");
    var button = section.querySelector("[data-pd-keygen-run]");
    var pass = section.querySelector("#pd-keygen-pass");
    var confirm = section.querySelector("#pd-keygen-confirm");
    var target = document.getElementById("pd-public-key");
    if (!subtle || !window.TextEncoder) { say(status, section.dataset.msgUnsupported, true); return; }
    button.disabled = false;
    button.addEventListener("click", function () {
      if (pass.value.length < 12) { say(status, section.dataset.msgTooShort, true); pass.focus(); return; }
      if (pass.value !== confirm.value) { say(status, section.dataset.msgMismatch, true); confirm.focus(); return; }
      button.disabled = true;
      button.classList.add("is-loading");
      say(status, section.dataset.msgGenerating);
      var pair;
      subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true, ["encrypt", "decrypt"]).then(function (generated) {
        pair = generated;
        return subtle.exportKey("pkcs8", pair.privateKey);
      }).then(function (pkcs8) {
        return encryptPkcs8(new Uint8Array(pkcs8), pass.value);
      }).then(function (encrypted) {
        download(section.dataset.filename, pem("ENCRYPTED PRIVATE KEY", encrypted));
        return subtle.exportKey("spki", pair.publicKey);
      }).then(function (spki) {
        spki = new Uint8Array(spki);
        if (target) {
          target.value = pem("PUBLIC KEY", spki);
          target.dispatchEvent(new Event("input"));
        }
        return fingerprint(spki);
      }).then(function (hex) {
        pass.value = "";
        confirm.value = "";
        say(status, section.dataset.msgGenerated + " " + grouped(hex));
        if (target) target.focus();
      }).catch(function () {
        say(status, section.dataset.msgFailed, true);
      }).then(function () {
        button.disabled = false;
        button.classList.remove("is-loading");
      });
    });
  }

  // --- Empreinte d'une clé publique collée -----------------------------------

  function setupPublicKey(form) {
    var area = form.querySelector("#pd-public-key");
    var status = form.querySelector("[data-pd-pubkey-status]");
    if (!subtle || !area) return;
    var show = function () {
      var parsed = unpem(area.value);
      if (!parsed) { say(status, ""); return; }
      if (parsed.label !== "PUBLIC KEY") { say(status, form.dataset.msgInvalid, true); return; }
      subtle.importKey("spki", parsed.der, RSA, true, ["encrypt"]).then(function () {
        return fingerprint(parsed.der);
      }).then(function (hex) {
        say(status, form.dataset.msgFingerprint + " " + grouped(hex));
      }).catch(function () { say(status, form.dataset.msgInvalid, true); });
    };
    area.addEventListener("input", show);
    show();
  }

  // --- Clé de données d'une sauvegarde (restauration) -------------------------

  function readKeyText(form) {
    var file = form.querySelector("[data-pd-key-file]");
    var text = form.querySelector("[data-pd-key-text]");
    if (file && file.files && file.files[0]) return file.files[0].text();
    return Promise.resolve(text ? text.value : "");
  }

  function importPrivate(text, passphrase) {
    var parsed = unpem(text);
    if (!parsed) return Promise.reject(new Error("PEM"));
    var pkcs8 = parsed.label === "ENCRYPTED PRIVATE KEY" ? decryptPkcs8(parsed.der, passphrase)
      : (parsed.label === "PRIVATE KEY" ? Promise.resolve(parsed.der) : Promise.reject(new Error("PEM")));
    return pkcs8.then(function (der) { return subtle.importKey("pkcs8", der, RSA, true, ["decrypt"]); });
  }

  function setupUnlock(form) {
    var status = form.querySelector("[data-pd-unlock-status]");
    var field = form.querySelector("[data-pd-data-key]");
    var secrets = form.querySelectorAll("[data-pd-key-file], [data-pd-key-text], [data-pd-key-pass]");
    var button = form.querySelector("button[type=submit]");
    if (!subtle || !window.TextEncoder) { say(status, form.dataset.msgUnsupported, true); if (button) button.disabled = true; return; }
    form.addEventListener("submit", function (event) {
      if (field.value) return;
      event.preventDefault();
      var pass = form.querySelector("[data-pd-key-pass]");
      readKeyText(form).then(function (text) {
        if (!text.trim()) { say(status, form.dataset.msgMissing, true); return null; }
        say(status, form.dataset.msgWorking);
        if (button) { button.disabled = true; button.classList.add("is-loading"); }
        var key;
        return importPrivate(text, pass ? pass.value : "").catch(function () {
          throw new Error("bad");
        }).then(function (imported) {
          key = imported;
          return privateFingerprint(key);
        }).then(function (hex) {
          if (hex !== form.dataset.fingerprint) throw new Error("wrong");
          return subtle.decrypt({ name: "RSA-OAEP" }, key, fromBase64(form.dataset.wrapped));
        }).then(function (dataKey) {
          field.value = toBase64(new Uint8Array(dataKey));
          // La clé privée et la phrase de passe ne partent jamais.
          Array.prototype.forEach.call(secrets, function (input) { input.value = ""; });
          form.submit();
        });
      }).catch(function (error) {
        say(status, error && error.message === "wrong" ? form.dataset.msgWrongKey : form.dataset.msgBadKey, true);
        if (button) { button.disabled = false; button.classList.remove("is-loading"); }
      });
    });
  }

  function init() {
    document.querySelectorAll("[data-pd-keygen]").forEach(setupKeygen);
    document.querySelectorAll("[data-pd-pubkey]").forEach(setupPublicKey);
    document.querySelectorAll("[data-pd-unlock]").forEach(setupUnlock);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
