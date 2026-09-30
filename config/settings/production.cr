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

  # Fichiers lus à l'exécution, rangés à côté des programmes installés.
  #
  # Marten lit les gabarits et les traductions de chaque application dans son
  # répertoire source, chemin fixé à la compilation, qui n'existe plus une
  # fois le programme installé par un paquet (aloli-ports,
  # finance/partiduo-admin). Le paquet collecte les fichiers statiques
  # (`partiduo-admin-manage collectassets`) dans `share/partiduo-admin/assets`
  # PUIS les gabarits et traductions (`collectartifacts --dest-path …`) dans
  # `share/partiduo-admin/artifacts`, à côté de `bin/` : une fois artifacts/
  # présent, il devient la racine des applications. Sans ces répertoires
  # (développement, essais), rien ne change. `PARTIDUO_ADMIN_ARTIFACTS_ROOT`
  # et `PARTIDUO_ADMIN_ASSETS_ROOT` restent prioritaires.
  share = Process.executable_path.try { |path| File.expand_path(File.join(File.dirname(path), "..", "share", "partiduo-admin")) }

  artifacts = ENV["PARTIDUO_ADMIN_ARTIFACTS_ROOT"]? || share.try { |dir| File.join(dir, "artifacts") }
  config.root_path = artifacts if artifacts && Dir.exists?(artifacts)

  # Fichiers statiques collectés (`partiduo-admin-manage collectassets`) :
  # la variable, sinon ceux du paquet, sinon `assets` du répertoire courant.
  config.assets.root = ENV["PARTIDUO_ADMIN_ASSETS_ROOT"]? ||
                       share.try { |dir| File.join(dir, "assets") }.try { |dir| Dir.exists?(dir) ? dir : nil } ||
                       "assets"
  config.middleware = [Marten::Middleware::AssetServing] + config.middleware
end
