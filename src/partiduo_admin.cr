# SPDX-License-Identifier: AGPL-3.0-or-later

# Point d'entrée de partiduo-admin (ADR-008) : application Marten séparée, avec
# sa propre base. Ne dépend pas de partiduo-app (ADR-008 D1) : l'exécutant
# parle aux instances par leur interface en ligne de commande.
require "marten"
require "pg"

require "./admin/app"

require "../config/settings/base"
require "../config/settings/**"
require "../config/routes"
