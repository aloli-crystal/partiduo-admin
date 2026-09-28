/* SPDX-License-Identifier: AGPL-3.0-or-later
   Clés d'accès (passkeys, WebAuthn — ADR-002 D2) : liaison entre les boutons
   [data-passkey] et navigator.credentials (DECISIONS D-UI-005). Toute règle
   est côté serveur : ce script transporte les options et la réponse de
   l'authentificateur, octets en base64url, et affiche le résultat.

   <button data-passkey="login|register|elevate" data-options-url="…"
           data-submit-url="…" data-status="<id>" [data-next="…"]
           [data-name-input="<id>"]> */
(function () {
  "use strict";

  function toBytes(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var raw = atob(b64);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function toB64url(buffer) {
    if (!buffer) return "";
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrf() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function post(url, fields) {
    var body = new URLSearchParams();
    Object.keys(fields || {}).forEach(function (key) { body.append(key, fields[key]); });
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf(), "Accept": "application/json" },
      body: body
    }).then(function (response) { return response.json(); });
  }

  function say(button, text) {
    var status = document.getElementById(button.getAttribute("data-status"));
    if (status) status.textContent = text;
  }

  function message(button, name) {
    var status = document.getElementById(button.getAttribute("data-status"));
    return status ? status.getAttribute("data-" + name) || "" : "";
  }

  function publicKeyForCreate(options) {
    var key = options.publicKey;
    key.challenge = toBytes(key.challenge);
    key.user.id = toBytes(key.user.id);
    key.excludeCredentials = (key.excludeCredentials || []).map(function (c) { return { type: c.type, id: toBytes(c.id) }; });
    return key;
  }

  function publicKeyForGet(options) {
    var key = options.publicKey;
    key.challenge = toBytes(key.challenge);
    key.allowCredentials = (key.allowCredentials || []).map(function (c) { return { type: c.type, id: toBytes(c.id) }; });
    return key;
  }

  function finish(button, outcome) {
    if (outcome.ok && outcome.redirect) { window.location.assign(outcome.redirect); return; }
    if (outcome.ok && outcome.html) {
      var content = document.getElementById("pd-content");
      content.innerHTML = outcome.html;
      var heading = content.querySelector("[tabindex='-1']");
      if (heading) heading.focus();
      return;
    }
    button.disabled = false;
    say(button, outcome.error || message(button, "failed"));
  }

  function run(button) {
    var mode = button.getAttribute("data-passkey");
    button.disabled = true;
    say(button, message(button, "waiting"));
    post(button.getAttribute("data-options-url")).then(function (options) {
      if (mode === "register") {
        return navigator.credentials.create({ publicKey: publicKeyForCreate(options) }).then(function (credential) {
          var nameInput = document.getElementById(button.getAttribute("data-name-input") || "");
          var transports = credential.response.getTransports ? credential.response.getTransports() : [];
          return post(button.getAttribute("data-submit-url"), {
            challenge_id: options.challengeId,
            attestation_object: toB64url(credential.response.attestationObject),
            client_data_json: toB64url(credential.response.clientDataJSON),
            transports: transports.join(","),
            name: nameInput ? nameInput.value : ""
          });
        });
      }
      return navigator.credentials.get({ publicKey: publicKeyForGet(options) }).then(function (credential) {
        return post(button.getAttribute("data-submit-url"), {
          challenge_id: options.challengeId,
          credential_id: toB64url(credential.rawId),
          authenticator_data: toB64url(credential.response.authenticatorData),
          client_data_json: toB64url(credential.response.clientDataJSON),
          signature: toB64url(credential.response.signature),
          user_handle: toB64url(credential.response.userHandle),
          next: button.getAttribute("data-next") || ""
        });
      });
    }).then(function (outcome) { finish(button, outcome); }, function () {
      button.disabled = false;
      say(button, message(button, "failed"));
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var supported = !!(window.PublicKeyCredential && navigator.credentials);
    document.querySelectorAll("[data-passkey]").forEach(function (button) {
      if (!supported) { button.disabled = true; say(button, message(button, "unsupported")); }
    });
  });

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof Element)) return;
    var button = target.closest("[data-passkey]");
    if (button && !button.disabled) { event.preventDefault(); run(button); }
  });
})();
