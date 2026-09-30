# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  module Commands
    # `manage bootstrap --email=… [--first-name=…] [--last-name=…] [--locale=fr]`
    #
    # Amorçage : crée le *premier* super-admin, sans secret, et affiche son
    # lien d'invitation (envoyé aussi par courriel s'il est configuré). Il
    # enrôle lui-même sa passkey, exigée pour son rôle (ADR-008 D2). Refusé
    # dès qu'un super-admin existe : les suivants sont invités depuis
    # l'interface. `--reinvite` réémet l'invitation du super-admin unique qui
    # n'aurait jamais enrôlé de passkey (lien perdu).
    class Bootstrap < Marten::CLI::Manage::Command::Base
      command_name :bootstrap
      help "Crée le premier super-admin par invitation (ADR-008 D2)."

      @email = ""
      @first_name = ""
      @last_name = ""
      @locale = "fr"
      @reinvite = false

      def setup
        on_option_with_arg("email", "adresse", "adresse du super-admin") { |value| @email = value }
        on_option_with_arg("first-name", "prenom", "prénom") { |value| @first_name = value }
        on_option_with_arg("last-name", "nom", "nom") { |value| @last_name = value }
        on_option_with_arg("locale", "langue", "fr, en ou nl") { |value| @locale = value }
        on_option("reinvite", "réémet l'invitation du super-admin sans passkey") { |_| @reinvite = true }
      end

      def run
        if @reinvite
          return reinvite
        end
        if User.filter(role: Config::SUPER_ADMIN).exists?
          return print_error_and_exit("un super-admin existe déjà : invitez les suivants depuis l'interface.")
        end
        outcome = Directory.invite_user(nil, Directory::UserInput.new(email: @email, first_name: @first_name,
          last_name: @last_name, role: Config::SUPER_ADMIN, locale: @locale))
        unless outcome.ok?
          outcome.errors.each { |field, keys| keys.each { |key| @stderr.puts("#{field} : #{I18n.t(key)}") } }
          return print_error_and_exit("amorçage refusé.")
        end
        user = outcome.value!
        # Le lien a été envoyé ; on en émet un nouveau pour l'afficher (le
        # précédent est annulé), l'opérateur n'ayant pas forcément de courriel.
        raw = Auth::Invitations.issue(user)
        print_link(user, raw)
      end

      private def reinvite
        users = User.filter(role: Config::SUPER_ADMIN).to_a
        user = users.find { |candidate| candidate.email == @email.strip.downcase }
        if user.nil?
          return print_error_and_exit("super-admin inconnu : #{@email}")
        end
        if Passkey.filter(user_id: user.pk).exists? && users.size > 1
          return print_error_and_exit("ce super-admin a une passkey : un autre super-admin réémet son invitation.")
        end
        raw = Auth::Invitations.issue(user)
        Audit.log(nil, "user.reinvite", target: user, actor_label: "bootstrap")
        print_link(user, raw)
      end

      private def print_link(user : User, raw : String) : Nil
        print("Super-admin : #{user.email}")
        print("Invitation (valable #{Config::INVITATION_TTL.days} jours) : #{Auth::Invitations.url(raw)}")
      end
    end

    # `manage schedule` : planification, à lancer toutes les quinze minutes
    # (cron, /usr/local/etc/cron.d/partiduo-admin) — sauvegardes planifiées,
    # élagage, restaurations test, supervision, alertes (ADR-008 D5).
    class Schedule < Marten::CLI::Manage::Command::Base
      command_name :schedule
      help "Planifie sauvegardes, élagages, restaurations test et supervision (ADR-008 D5)."

      def run
        summary = Scheduler.run
        print("sauvegardes : #{summary.backups}, élagages : #{summary.prunes}, " \
              "restaurations test : #{summary.test_restores}, supervisions : #{summary.checks}")
      end
    end
  end
end
