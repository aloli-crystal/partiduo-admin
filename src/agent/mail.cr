# SPDX-License-Identifier: AGPL-3.0-or-later

require "base64"
require "random/secure"

module PartiduoAgent
  # Courriel d'invitation de l'administrateur d'un dossier, remis par le
  # serveur lui-même (D-CRA-003) : le lien d'invitation ne quitte jamais le
  # serveur d'hébergement, l'administration n'en voit que la trace
  # (`invitation_delivered`). Une faille de l'administration ne donne donc
  # pas le lien qui ouvre un compte d'administrateur de dossier (ADR-008 D3,
  # « Conséquences positives »).
  #
  # Envoi par la commande `--mail-command` (par exemple
  # `/usr/sbin/sendmail -oi`), lancée sans shell, message RFC 5322 sur
  # l'entrée standard, destinataire en dernier argument.
  module InvitationMail
    # Adresse sûre : ni espace, ni retour à la ligne, ni séparateur d'en-tête,
    # jamais prise pour une option.
    ADDRESS = /\A[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\z/

    # Mêmes textes que `admin.emails.dossier_invitation` de l'administration.
    TEXTS = {
      "fr" => {
        "subject" => "Invitation à administrer le dossier %{host}",
        "intro"   => "Vous êtes invité à administrer le dossier Partiduo %{host}. Ouvrez ce lien pour créer votre accès :",
        "ignore"  => "Si vous n'attendiez pas ce message, ignorez-le.",
      },
      "en" => {
        "subject" => "Invitation to administer the company file %{host}",
        "intro"   => "You are invited to administer the Partiduo company file %{host}. Open this link to create your access:",
        "ignore"  => "If you were not expecting this message, ignore it.",
      },
      "nl" => {
        "subject" => "Uitnodiging om het dossier %{host} te beheren",
        "intro"   => "U bent uitgenodigd om het Partiduo-dossier %{host} te beheren. Open deze link om uw toegang aan te maken:",
        "ignore"  => "Als u dit bericht niet verwachtte, negeer het dan.",
      },
    }

    def self.valid_address?(address : String) : Bool
      ADDRESS.matches?(address) && !address.starts_with?('-')
    end

    def self.text(locale : String, key : String, host : String) : String
      (TEXTS[locale]? || TEXTS["fr"])[key].gsub("%{host}", host)
    end

    def self.encode_header(text : String) : String
      text.ascii_only? ? text : "=?UTF-8?B?#{Base64.strict_encode(text)}?="
    end

    # Message complet (en-têtes et corps), lignes terminées par CRLF.
    def self.build(from : String, to : String, host : String, url : String, locale : String,
                   date : Time = Time.utc) : String
      body = "#{text(locale, "intro", host)}\n\n#{url}\n\n#{text(locale, "ignore", host)}\n"
      String.build do |io|
        io << "From: " << from << "\r\n"
        io << "To: " << to << "\r\n"
        io << "Subject: " << encode_header(text(locale, "subject", host)) << "\r\n"
        io << "Date: " << date.to_rfc2822 << "\r\n"
        io << "Message-ID: <" << Random::Secure.hex(12) << "@partiduo-agent>\r\n"
        io << "MIME-Version: 1.0\r\n"
        io << "Content-Type: text/plain; charset=UTF-8\r\n"
        io << "Content-Transfer-Encoding: base64\r\n\r\n"
        io << Base64.encode(body).gsub("\n", "\r\n")
      end
    end
  end
end
