# SPDX-License-Identifier: AGPL-3.0-or-later

# partiduo-agent — exécutant de partiduo-admin (ADR-008 D4), installé sur
# chaque serveur d'hébergement sous un utilisateur système dédié. Il tire ses
# tâches de l'API de l'admin en HTTPS avec le jeton du serveur, et n'accepte
# qu'une liste fermée de types de tâches.
require "log"
require "./agent/lib"

begin
  config = PartiduoAgent::Config.parse(ARGV)
  if config.production? && config.mail_command.strip.empty?
    STDERR.puts "partiduo-agent : sans --mail-command, les liens d'invitation passent par l'administration (D-CRA-003)"
  end
  PartiduoAgent::Runner.new(config).run
rescue ex : ArgumentError | OptionParser::Exception
  STDERR.puts "partiduo-agent : #{ex.message}"
  exit 2
end
