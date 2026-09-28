# SPDX-License-Identifier: AGPL-3.0-or-later

ENV["MARTEN_ENV"] = "test"
ENV["PARTIDUO_DOMAIN"] = "partiduo.localhost"

require "spec"

require "../src/cli"
require "marten/spec"
require "../src/agent/lib"

require "./support/**"

# Horloge figée : les règles datées (baux, rétention, supervision) restent
# vraies quel que soit le jour où les specs tournent.
SPEC_NOW = Time.utc(2026, 9, 28, 10, 0, 0)
PartiduoAdmin::Config.clock = -> { SPEC_NOW }
