# SPDX-License-Identifier: AGPL-3.0-or-later

# `crystal run manage.cr -- <commande>` : migrate, genmigrations, bootstrap,
# schedule…
require "./src/cli"

Marten.setup
Marten::CLI.run
