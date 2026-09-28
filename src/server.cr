# SPDX-License-Identifier: AGPL-3.0-or-later

# Serveur HTTP de l'administration : `crystal run src/server.cr` (ou le
# binaire `partiduo-admin` produit par `shards build`).
require "./partiduo_admin"

Marten.start
