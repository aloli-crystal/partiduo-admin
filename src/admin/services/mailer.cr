# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Courriel texte : invitations et alertes.
  class TextEmail < Marten::Email
    from Config.mail_from
    to @address
    subject @title

    def initialize(@address : String, @title : String, @body : String)
    end

    def text_body : String?
      @body
    end
  end

  module Mailer
    # Invitation d'un utilisateur de l'administration (amorçage, création,
    # réémission).
    def self.invitation(user : User, url : String) : Nil
      I18n.with_locale(user.locale.presence || "fr") do
        body = String.build do |io|
          io << I18n.t("admin.emails.invitation.intro") << "\n\n" << url << "\n\n"
          io << I18n.t("admin.emails.invitation.expires", days: Config::INVITATION_TTL.days.to_s) << "\n"
          io << I18n.t("admin.emails.ignore") << "\n"
        end
        TextEmail.new(user.email.to_s, I18n.t("admin.emails.invitation.subject"), body).deliver
      end
    end

    # Invitation de l'administrateur d'un dossier (création, recours
    # d'accès) : le lien vient de l'instance, n'est pas conservé ici.
    def self.invitation_to_dossier(dossier : Dossier, email : String, url : String) : Nil
      I18n.with_locale(dossier.locale.presence || "fr") do
        body = String.build do |io|
          io << I18n.t("admin.emails.dossier_invitation.intro", host: dossier.host) << "\n\n" << url << "\n\n"
          io << I18n.t("admin.emails.ignore") << "\n"
        end
        TextEmail.new(email, I18n.t("admin.emails.dossier_invitation.subject", host: dossier.host), body).deliver
      end
    end

    def self.alert(alert : Alert) : Nil
      recipients = Config.alert_recipients
      return if recipients.empty?
      subject = I18n.t("admin.emails.alert.subject", kind: I18n.t(alert.kind_key), subject: alert.subject)
      body = "#{I18n.t(alert.kind_key)} — #{alert.subject}\n#{alert.detail}\n\n#{Config.base_url}/alerts\n"
      recipients.each { |address| TextEmail.new(address, subject, body).deliver }
    rescue ex
      Log.warn { "alerte non envoyée : #{ex.message}" }
    end
  end
end
