# SPDX-License-Identifier: AGPL-3.0-or-later

require "../shared/protocol"
require "../shared/backup_crypto"
require "./config"
require "./models/organization"
require "./models/security"
require "./models/fleet"
require "./services/secrets"
require "./services/audit"
require "./services/auth"
require "./services/passkeys"
require "./services/access"
require "./services/mailer"
require "./services/tasks"
require "./services/effects"
require "./services/fleet"
require "./services/backup_encryption"
require "./services/approvals"
require "./services/supervision"
require "./services/directory"
require "./handlers/concerns/base"
require "./handlers/auth_handlers"
require "./handlers/dossier_handlers"
require "./handlers/fleet_handlers"
require "./handlers/directory_handlers"
require "./handlers/encryption_handlers"
require "./handlers/agent_api"

module PartiduoAdmin
  VERSION = "0.1.0"

  # Application Marten de l'administration du parc (ADR-008) : modèles,
  # gabarits (`templates/admin/`), fichiers statiques (`assets/admin/`),
  # libellés (`locales/`).
  class App < Marten::App
    label "admin"
  end
end
