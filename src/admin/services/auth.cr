# SPDX-License-Identifier: AGPL-3.0-or-later

# Seul le hachage d'authn : `require "authn"` charge `jwt`, dont
# `openssl_ext` entre en conflit avec `jose` (partiduo-app, B-AUTH-002).
require "authn/password"
require "totp"

module PartiduoAdmin
  # Authentification de l'administration (ADR-002, ADR-008 D2), sur les
  # shards maison : `password-policy` et `authn` (mot de passe), `totp`,
  # `webauthn` (voir `Passkeys`).
  module Auth
    ENROLLMENT = 0
    PASSWORD   = 1
    TWO_FACTOR = 2
    PASSKEY    = 3

    # Niveau exigé (ADR-008 D2) : passkey pour le super-admin, niveau 2
    # minimum pour les autres rôles.
    def self.required_level(user : User) : Int32
      user.super_admin? ? PASSKEY : TWO_FACTOR
    end

    # Ce qui manque pour atteindre le niveau exigé : `password`, `totp`,
    # `passkey`, `recovery_codes`.
    def self.missing(user : User) : Array(String)
      missing = [] of String
      has_passkey = Passkey.filter(user_id: user.pk).exists?
      if user.super_admin?
        missing << "passkey" unless has_passkey
      elsif !has_passkey
        missing << "password" unless user.usable_password?
        missing << "totp" unless user.totp_enabled?
      end
      missing << "recovery_codes" if (has_passkey || user.totp_enabled?) && RecoveryCodes.remaining(user).zero?
      missing
    end

    module Passwords
      @@decoy : String?

      # Clés `admin.errors.password.<motif>` (motifs de `PasswordPolicy`).
      def self.errors(password : String, user : User? = nil) : Array(String)
        errors = Config.password_policy.validate(password).map do |violation|
          "admin.errors.password.#{violation.to_s.underscore}"
        end
        if user
          words = [user.email.to_s.split('@').first? || "", user.first_name.to_s, user.last_name.to_s].select { |word| word.size >= 4 }
          lowered = password.downcase
          errors << "admin.errors.password.personal" if words.any? { |word| lowered.includes?(word.downcase) }
        end
        errors
      end

      def self.hash(password : String) : String
        Authn::Password.hash(password, cost: Config.bcrypt_cost, policy: Config.password_policy)
      end

      # Vérification en temps constant, même pour une adresse inconnue.
      def self.verify(user : User?, password : String) : Bool
        digest = user.try(&.password_digest)
        if user.nil? || digest.nil?
          Authn::Password.verify(password, decoy)
          return false
        end
        Authn::Password.verify(password, digest)
      end

      private def self.decoy : String
        @@decoy ||= Authn::Password.hash(Secrets.token, cost: Config.bcrypt_cost)
      end
    end

    # TOTP (RFC 6238 : SHA-1, 6 chiffres, 30 s), anti-rejeu par le compteur
    # accepté, enregistré par une mise à jour conditionnelle.
    module Totp
      def self.authenticator(secret : String) : TOTP::Authenticator
        TOTP::Authenticator.from_base32(secret)
      end

      def self.begin(user : User) : String
        secret = TOTP.generate_secret_base32
        user.totp_pending_secret = secret
        user.save!
        secret
      end

      def self.provisioning_uri(user : User, secret : String) : String
        authenticator(secret).provisioning_uri(account: user.email.to_s, issuer: Config::ISSUER)
      end

      # Confirme l'enrôlement par un code du secret en attente.
      def self.confirm(user : User, code : String, now : Time = Time.utc) : Bool
        secret = user.totp_pending_secret
        return false if secret.nil?
        counter = authenticator(secret).verify(code, time: now)
        return false if counter.nil?
        user.totp_secret = secret
        user.totp_pending_secret = nil
        user.totp_enabled_at = now
        user.last_otp_counter = counter.to_i64
        user.save!
        true
      end

      def self.verify!(user : User, code : String, now : Time = Time.utc) : Bool
        secret = user.totp_secret
        return false if secret.nil? || !user.totp_enabled?
        after = user.last_otp_counter.try(&.to_u64)
        counter = authenticator(secret).verify(code, time: now, after: after)
        return false if counter.nil?
        value = counter.to_i64
        claimed = User.filter(id: user.pk, totp_secret: secret)
          .filter { q(last_otp_counter__isnull: true) | q(last_otp_counter__lt: value) }
          .update(last_otp_counter: value)
        return false unless claimed == 1
        user.last_otp_counter = value
        true
      end
    end

    # Codes de récupération (ADR-002 D7) : 16 caractères, empreinte SHA-256.
    module RecoveryCodes
      ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

      def self.remaining(user : User) : Int32
        RecoveryCode.filter(user_id: user.pk, used_at__isnull: true).count.to_i32
      end

      def self.generate(user : User) : Array(String)
        RecoveryCode.filter(user_id: user.pk).delete
        Array.new(Config::RECOVERY_CODES) do
          code = String.build do |io|
            16.times do |index|
              io << '-' if index > 0 && index % 4 == 0
              io << ALPHABET[Random::Secure.rand(ALPHABET.size)]
            end
          end
          RecoveryCode.create!(user: user, code_digest: Secrets.digest(normalize(code)))
          code
        end
      end

      def self.ensure(user : User) : Array(String)
        remaining(user).zero? ? generate(user) : [] of String
      end

      def self.consume!(user : User, code : String, now : Time = Time.utc) : Bool
        RecoveryCode.filter(user_id: user.pk, code_digest: Secrets.digest(normalize(code)), used_at__isnull: true)
          .update(used_at: now) == 1
      end

      def self.normalize(code : String) : String
        code.upcase.gsub(/[^A-Z0-9]/, "")
      end
    end

    # Limitation des tentatives (ADR-002, CNIL 2022-100) : réservation
    # atomique avant l'examen du secret, temporisation croissante à partir du
    # 3ᵉ échec, blocage au 10ᵉ (même mécanisme que partiduo-app, D-AUTH-012).
    module Throttle
      record Reservation, granted : Bool, locked : Bool = false, wait : Time::Span? = nil,
        reserved_at : Time? = nil, previous_failed_at : Time? = nil

      RESERVE_SQL = <<-SQL
        WITH previous AS (
          SELECT id, last_failed_at FROM admin_user WHERE id = $1 FOR UPDATE
        )
        UPDATE admin_user AS target
           SET failed_attempts = target.failed_attempts + 1,
               last_failed_at = $2
          FROM previous
         WHERE target.id = previous.id
           AND target.locked_at IS NULL
           AND (target.failed_attempts < $3
                OR target.last_failed_at IS NULL
                OR target.last_failed_at
                   + make_interval(secs => LEAST($4 * power(2, LEAST(target.failed_attempts - $3, 20)), $5))
                   <= $2)
        RETURNING target.failed_attempts, previous.last_failed_at
        SQL

      CONFIRM_SQL = <<-SQL
        UPDATE admin_user
           SET locked_at = CASE WHEN failed_attempts >= $3 AND locked_at IS NULL THEN $2 ELSE locked_at END
         WHERE id = $1
        RETURNING failed_attempts
        SQL

      RELEASE_SQL = <<-SQL
        UPDATE admin_user
           SET failed_attempts = GREATEST(failed_attempts - 1, 0),
               last_failed_at = CASE WHEN last_failed_at = $2 THEN $3 ELSE last_failed_at END
         WHERE id = $1 AND failed_attempts > 0
        SQL

      def self.delay_for(failures : Int32) : Time::Span
        return Time::Span.zero if failures < Config::THROTTLE_AFTER
        delay = Config::THROTTLE_BASE * (2 ** (failures - Config::THROTTLE_AFTER).clamp(0, 20))
        delay > Config::THROTTLE_MAXIMUM ? Config::THROTTLE_MAXIMUM : delay
      end

      def self.reserve(user : User, now : Time = Time.utc) : Reservation
        now = now.at_beginning_of_second + (now.nanosecond // 1000).microseconds
        row = Marten::DB::Connection.default.open do |db|
          db.query_one?(RESERVE_SQL, user.pk!.as(Int64), now, Config::THROTTLE_AFTER,
            Config::THROTTLE_BASE.total_seconds.to_i, Config::THROTTLE_MAXIMUM.total_seconds.to_i,
            as: {Int32, Time?})
        end
        if row
          user.failed_attempts = row[0]
          user.last_failed_at = now
          return Reservation.new(granted: true, reserved_at: now, previous_failed_at: row[1])
        end
        user.reload
        return Reservation.new(granted: false, locked: true) if user.locked?
        failures = (user.failed_attempts || 0).to_i32
        wait = (user.last_failed_at || now) + delay_for(failures) - now
        Reservation.new(granted: false, wait: wait > Time::Span.zero ? wait : 1.second)
      end

      def self.confirm_failure(user : User, now : Time = Time.utc) : Nil
        Marten::DB::Connection.default.open do |db|
          db.exec(CONFIRM_SQL.sub("RETURNING failed_attempts", ""), user.pk!.as(Int64), now, Config::LOCK_AFTER)
        end
        user.reload
      end

      def self.release(user : User, reservation : Reservation) : Nil
        reserved_at = reservation.reserved_at
        return unless reservation.granted && reserved_at
        Marten::DB::Connection.default.open do |db|
          db.exec(RELEASE_SQL, user.pk!.as(Int64), reserved_at, reservation.previous_failed_at)
        end
        user.reload
      end

      def self.record_success(user : User) : Nil
        User.filter(id: user.pk).update(failed_attempts: 0, last_failed_at: nil)
        user.failed_attempts = 0
        user.last_failed_at = nil
      end

      def self.unlock(user : User) : Nil
        User.filter(id: user.pk).update(failed_attempts: 0, last_failed_at: nil, locked_at: nil)
        user.reload
      end
    end

    # Défis à usage unique : le client tient une poignée, la base son
    # empreinte ; la consommation marque la ligne dans la même instruction.
    module Challenges
      record Issued, challenge : Challenge, handle : String

      def self.issue(purpose : String, user : User? = nil, value : String = "",
                     ttl : Time::Span = Config::CHALLENGE_TIMEOUT, now : Time = Time.utc) : Issued
        Challenge.filter(expires_at__lt: now - 1.day).delete if Random.rand(50).zero?
        handle = Secrets.token
        challenge = Challenge.create!(purpose: purpose, handle_digest: Secrets.digest(handle), value: value,
          user: user, expires_at: now + ttl)
        Issued.new(challenge, handle)
      end

      def self.consume(purpose : String, handle : String?, now : Time = Time.utc) : Challenge?
        return if handle.nil? || handle.empty?
        digest = Secrets.digest(handle)
        claimed = Challenge.filter(handle_digest: digest, purpose: purpose, used_at__isnull: true, expires_at__gt: now)
          .update(used_at: now)
        claimed == 1 ? Challenge.get(handle_digest: digest) : nil
      end

      def self.peek(purpose : String, handle : String?, now : Time = Time.utc) : Challenge?
        return if handle.nil? || handle.empty?
        Challenge.filter(handle_digest: Secrets.digest(handle), purpose: purpose, used_at__isnull: true,
          expires_at__gt: now).first
      end
    end

    module Sessions
      record Opened, session : Session, token : String

      def self.open(user : User, level : Int32, method : String, ip : String = "", user_agent : String = "",
                    now : Time = Time.utc) : Opened
        token = Secrets.token
        session = Session.create!(user: user, token_digest: Secrets.digest(token), level: level, method: method,
          ip: ip[0, 64], user_agent: user_agent[0, 255], last_seen_at: now, expires_at: now + Config::SESSION_LIFETIME)
        if level > ENROLLMENT
          user.last_login_at = now
          user.save!
        end
        Opened.new(session, token)
      end

      def self.find(token : String?, now : Time = Time.utc) : Session?
        return if token.nil? || token.empty?
        session = Session.filter(token_digest: Secrets.digest(token)).first
        return if session.nil? || !session.revoked_at.nil?
        return if session.expires_at! < now || session.last_seen_at! + Config::IDLE_TIMEOUT < now
        user = session.user
        return if user.nil? || !user.can_sign_in?
        if session.last_seen_at! + 1.minute < now
          session.last_seen_at = now
          session.save!
        end
        session
      end

      def self.raise_level(session : Session, level : Int32, method : String) : Nil
        return if (session.level || 0) >= level
        session.level = level
        session.method = method
        session.save!
      end

      def self.revoke(session : Session, now : Time = Time.utc) : Nil
        return unless session.revoked_at.nil?
        session.revoked_at = now
        session.save!
      end

      def self.revoke_all(user : User, now : Time = Time.utc, except : Int64? = nil) : Nil
        sessions = Session.filter(user_id: user.pk, revoked_at__isnull: true)
        sessions = sessions.exclude(id: except) if except
        sessions.update(revoked_at: now)
      end
    end

    # Invitations : premier accès (amorçage, création d'un utilisateur) et
    # recours (réémission par un super-admin ou l'admin du cabinet).
    module Invitations
      def self.issue(user : User, by : User? = nil, now : Time = Time.utc) : String
        Invitation.filter(user_id: user.pk, used_at__isnull: true).update(used_at: now)
        raw = Secrets.token
        Invitation.create!(digest: Secrets.digest(raw), user: user, created_by_id: by.try(&.pk),
          expires_at: now + Config::INVITATION_TTL)
        raw
      end

      def self.url(raw : String) : String
        "#{Config.base_url}/invitation/#{raw}"
      end

      def self.consume(raw : String?, now : Time = Time.utc) : User?
        return if raw.nil? || raw.empty?
        digest = Secrets.digest(raw)
        claimed = Invitation.filter(digest: digest, used_at__isnull: true, expires_at__gt: now).update(used_at: now)
        return unless claimed == 1
        Invitation.get(digest: digest).try(&.user)
      end

      def self.peek(raw : String?, now : Time = Time.utc) : User?
        return if raw.nil? || raw.empty?
        Invitation.filter(digest: Secrets.digest(raw), used_at__isnull: true, expires_at__gt: now).first.try(&.user)
      end
    end

    # Connexion par mot de passe, puis second facteur. Renvoie une clé
    # d'erreur, une session ouverte, ou un second facteur attendu.
    record LoginResult, error : String? = nil, opened : Sessions::Opened? = nil,
      pending : String? = nil, wait : Time::Span? = nil

    PURPOSE_PENDING = "second_factor"

    def self.login_password(email : String, password : String, ip : String = "", user_agent : String = "",
                            now : Time = Time.utc) : LoginResult
      user = User.filter(email: email.strip.downcase).first
      if user.nil? || !user.can_sign_in?
        Passwords.verify(nil, password)
        Audit.log(nil, "auth.login", outcome: "fail", detail: {"email" => email.strip.downcase, "reason" => "unknown"}, ip: ip)
        return LoginResult.new(error: "admin.errors.login.invalid")
      end
      reservation = Throttle.reserve(user, now)
      unless reservation.granted
        key = reservation.locked ? "admin.errors.login.locked" : "admin.errors.login.wait"
        return LoginResult.new(error: key, wait: reservation.wait)
      end
      unless Passwords.verify(user, password)
        Throttle.confirm_failure(user, now)
        Audit.log(user, "auth.login", outcome: "fail", target: user, detail: {"reason" => "password"}, ip: ip)
        return LoginResult.new(error: user.locked? ? "admin.errors.login.locked" : "admin.errors.login.invalid")
      end
      if user.totp_enabled?
        Throttle.release(user, reservation)
        issued = Challenges.issue(PURPOSE_PENDING, user: user, ttl: Config::PENDING_LIFETIME, now: now)
        return LoginResult.new(pending: issued.handle)
      end
      Throttle.record_success(user)
      Audit.log(user, "auth.login", target: user, detail: {"level" => PASSWORD.to_s}, ip: ip)
      LoginResult.new(opened: Sessions.open(user, PASSWORD, "password", ip, user_agent, now))
    end

    # Second facteur : code TOTP ou code de récupération.
    def self.login_second_factor(handle : String?, code : String, ip : String = "", user_agent : String = "",
                                 now : Time = Time.utc) : LoginResult
      challenge = Challenges.peek(PURPOSE_PENDING, handle, now)
      user = challenge.try(&.user)
      return LoginResult.new(error: "admin.errors.login.expired") if challenge.nil? || user.nil? || !user.can_sign_in?
      reservation = Throttle.reserve(user, now)
      unless reservation.granted
        key = reservation.locked ? "admin.errors.login.locked" : "admin.errors.login.wait"
        return LoginResult.new(error: key, wait: reservation.wait)
      end
      cleaned = code.strip
      method = nil
      if cleaned.gsub(/\s/, "").matches?(/\A\d{6}\z/)
        method = "totp" if Totp.verify!(user, cleaned.gsub(/\s/, ""), now)
      elsif RecoveryCodes.consume!(user, cleaned, now)
        method = "recovery_code"
      end
      if method.nil?
        Throttle.confirm_failure(user, now)
        Audit.log(user, "auth.second_factor", outcome: "fail", target: user, ip: ip)
        return LoginResult.new(error: user.locked? ? "admin.errors.login.locked" : "admin.errors.login.code")
      end
      Challenges.consume(PURPOSE_PENDING, handle, now)
      Throttle.record_success(user)
      Audit.log(user, "auth.login", target: user, detail: {"level" => TWO_FACTOR.to_s, "method" => method}, ip: ip)
      LoginResult.new(opened: Sessions.open(user, TWO_FACTOR, method, ip, user_agent, now))
    end
  end
end
