# SPDX-License-Identifier: AGPL-3.0-or-later

Marten.configure :production do |config|
  config.debug = false
  config.secret_key = ENV.fetch("MARTEN_SECRET_KEY")
  config.host = "127.0.0.1"
  config.port = (ENV["PORT"]? || "8200").to_i

  # Derrière le serveur mandataire de `admin.<domaine>` (ADR-008 D1), qui
  # termine TLS et pose `X-Forwarded-Proto`.
  config.use_x_forwarded_proto = true
  config.sessions.cookie_secure = true
  config.sessions.cookie_http_only = true
  config.csrf.cookie_secure = true
  config.csrf.cookie_http_only = true
  config.templates.cached = true

  # Fichiers statiques collectés (`partiduo-admin-manage collectassets`).
  config.assets.root = ENV["PARTIDUO_ADMIN_ASSETS_ROOT"]? || "assets"
  config.middleware = [Marten::Middleware::AssetServing] + config.middleware
end
