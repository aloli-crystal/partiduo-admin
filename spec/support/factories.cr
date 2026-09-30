# SPDX-License-Identifier: AGPL-3.0-or-later

require "totp"

module AdminSpec
  PASSWORD = "Correcthorse42battery"
  ORIGIN   = "http://admin.partiduo.localhost:8200"

  @@sequence = 0

  def self.next_id : Int32
    @@sequence += 1
  end

  def self.firm(name : String = "Cabinet #{next_id}") : PartiduoAdmin::Firm
    PartiduoAdmin::Firm.create!(name: name)
  end

  # Utilisateur prêt à l'emploi : mot de passe et TOTP (niveau 2) sauf
  # super-admin (passkey, voir `Authenticator`).
  def self.user(role : String = PartiduoAdmin::Config::FIRM_ADMIN, firm : PartiduoAdmin::Firm? = nil,
                email : String? = nil, password : Bool = true, totp : Bool = true) : PartiduoAdmin::User
    user = PartiduoAdmin::User.create!(email: email || "user#{next_id}@example.com", role: role,
      firm: role == PartiduoAdmin::Config::SUPER_ADMIN ? nil : (firm || self.firm), first_name: "Jeanne", last_name: "Durand")
    if password
      user.password_digest = PartiduoAdmin::Auth::Passwords.hash(PASSWORD)
    end
    if totp
      user.totp_secret = TOTP.generate_secret_base32
      user.totp_enabled_at = SPEC_NOW - 1.day
    end
    user.save!
    user
  end

  def self.super_admin : PartiduoAdmin::User
    user(PartiduoAdmin::Config::SUPER_ADMIN, password: false, totp: false)
  end

  def self.server(name : String = "srv#{next_id}", domain : String = "partiduo.localhost") : {PartiduoAdmin::Server, String}
    token = PartiduoAdmin::Secrets.token
    server = PartiduoAdmin::Server.create!(name: name, hostname: "#{name}.example.net", domain: domain,
      token_digest: PartiduoAdmin::Secrets.digest(token))
    {server, token}
  end

  def self.payer(firm : PartiduoAdmin::Firm, kind : String = "company", name : String = "Payeur #{next_id}") : PartiduoAdmin::Payer
    PartiduoAdmin::Payer.create!(kind: kind, firm: firm, name: name, siren: "732829320", street: "1 rue de la Paix",
      postcode: "75002", city: "Paris", country: "FR", contact_name: "M. Martin", contact_email: "compta@example.com")
  end

  def self.dossier(firm : PartiduoAdmin::Firm, server : PartiduoAdmin::Server, state : String = "active",
                   slug : String = "dossier#{next_id}", payer : PartiduoAdmin::Payer? = nil,
                   version : String = "0.1.0", package : String = "app") : PartiduoAdmin::Dossier
    PartiduoAdmin::Dossier.create!(slug: slug, label: "Société #{slug}", regime: "fr", modules: "accounting,invoicing",
      admin_email: "patron@#{slug}.example.com", server: server, firm: firm, payer: payer || self.payer(firm),
      state: state, version: version, package: package, database: "partiduo_adm_#{slug.tr("-", "_")}")
  end

  def self.totp_code(user : PartiduoAdmin::User, time : Time = Time.utc) : String
    TOTP::Authenticator.from_base32(user.totp_secret.to_s).at(time)
  end

  # Session ouverte au niveau voulu ; renvoie le jeton du cookie.
  def self.session(user : PartiduoAdmin::User, level : Int32? = nil) : String
    level ||= PartiduoAdmin::Auth.required_level(user)
    PartiduoAdmin::Auth::Sessions.open(user, level, "spec", now: SPEC_NOW).token
  end

  def self.backup(dossier : PartiduoAdmin::Dossier, taken_at : Time = SPEC_NOW - 1.day, kind : String = "scheduled") : PartiduoAdmin::Backup
    PartiduoAdmin::Backup.create!(dossier: dossier, kind: kind, state: "done", path: "/var/backups/partiduo/#{dossier.slug}/b.dump",
      media_path: "/var/backups/partiduo/#{dossier.slug}/b.media.tar.gz", sha256: "0" * 64, taken_at: taken_at,
      keep_until: taken_at + 30.days, version: dossier.version.to_s)
  end
end
