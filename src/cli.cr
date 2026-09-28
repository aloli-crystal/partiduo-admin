# SPDX-License-Identifier: AGPL-3.0-or-later

# Ligne de commande Marten de l'administration : migrations et commandes
# `bootstrap` (premier super-admin) et `schedule` (planification).
require "./partiduo_admin"
require "marten/cli"
require "./admin/migrations/**"
require "./admin/commands/**"
