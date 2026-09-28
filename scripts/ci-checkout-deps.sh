#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# shard.yml référence les shards maison en `path: ../../<nom>` tant qu'ils ne
# sont pas publiés. En CI, on les clone à cet emplacement, à côté du dépôt
# (dépôts publics de https://github.com/aloli-crystal).
set -eu

cd "$(dirname "$0")/.."
target="$(cd ../.. && pwd)"
base="${PARTIDUO_DEPS_BASE_URL:-https://github.com/aloli-crystal}"

for shard in marten authn password-policy totp webauthn jose; do
  if [ ! -d "$target/$shard" ]; then
    git clone --depth 1 "$base/$shard.git" "$target/$shard"
  fi
done
