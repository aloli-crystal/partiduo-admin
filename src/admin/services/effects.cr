# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  module Tasks
    # Effets d'une tâche terminée sur l'inventaire : état et version du
    # dossier, sauvegardes, certificats, supervision, progression des vagues.
    module Effects
      # Clés du résultat jamais conservées : le lien d'invitation et son
      # jeton ne sont écrits nulle part ailleurs que dans le courriel envoyé
      # à l'adresse invitée (instance-cli, `admin-invite`).
      SECRET_KEYS = %w[url token invitation_url]

      def self.sanitize(task : Task, result : JSON::Any) : JSON::Any
        hash = result.as_h?
        return result if hash.nil?
        JSON::Any.new(hash.reject { |key, _| SECRET_KEYS.includes?(key) })
      end

      alias Handler = Proc(Task, Dossier, Bool, JSON::Any, Time, Nil)

      # Effet de chaque type de tâche portant sur un dossier.
      HANDLERS = {
        "instance.create"          => Handler.new { |task, dossier, success, result, now| created(task, dossier, success, result, now) },
        "instance.modules"         => Handler.new { |task, dossier, success, _, _| modules(dossier, success, task) },
        "instance.suspend"         => Handler.new { |_, dossier, success, _, now| state(dossier, success, "suspended", now) },
        "instance.resume"          => Handler.new { |_, dossier, success, _, now| state(dossier, success, "active", now) },
        "instance.restore_archive" => Handler.new { |_, dossier, success, _, now| state(dossier, success, "active", now) },
        "instance.archive"         => Handler.new { |task, dossier, success, result, now| archived(task, dossier, success, result, now) },
        "instance.delete"          => Handler.new { |_, dossier, success, _, now| deleted(dossier, success, now) },
        "instance.upgrade"         => Handler.new { |task, dossier, success, result, now| upgraded(task, dossier, success, result, now) },
        "instance.admin_invite"    => Handler.new { |task, dossier, success, result, _| invited(task, dossier, success, result) },
        "backup.run"               => Handler.new { |task, dossier, success, result, now| backed_up(task, dossier, success, result, now) },
        "backup.prune"             => Handler.new { |task, _, success, _, now| pruned(task, success, now) },
        "backup.test_restore"      => Handler.new { |task, _, success, _, now| test_restored(task, success, now) },
        "backup.restore"           => Handler.new { |task, dossier, success, result, now| restored(task, dossier, success, result, now) },
      }

      def self.apply(task : Task, ok : Bool, result : JSON::Any, now : Time) : Nil
        if task.kind == "supervision.check"
          Supervision.apply(task.server!, ok, result, now)
          return
        end
        dossier = task.dossier
        return if dossier.nil?
        HANDLERS[task.kind]?.try(&.call(task, dossier, ok, result, now))
      end

      def self.created(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any, now : Time) : Nil
        unless ok
          dossier.state = "error"
          dossier.save!
          return
        end
        dossier.state = "active"
        dossier.database = result["database"]?.try(&.as_s?) || dossier.database
        dossier.version = result["version"]?.try(&.as_s?) || dossier.version
        dossier.save!
        record_certificate(dossier, result, now)
        if url = result["invitation_url"]?.try(&.as_s?)
          Mailer.invitation_to_dossier(dossier, dossier.admin_email.to_s, url)
        end
      end

      def self.modules(dossier : Dossier, ok : Bool, task : Task) : Nil
        return unless ok
        params = task.params_json
        dossier.modules = params["target_modules"]?.try(&.as_a.map(&.as_s).join(',')) || dossier.modules
        dossier.extensions = params["target_extensions"]?.try(&.as_a.map(&.as_s).join(',')) || dossier.extensions
        dossier.save!
      end

      def self.state(dossier : Dossier, ok : Bool, state : String, now : Time) : Nil
        return unless ok
        dossier.state = state
        dossier.suspended_at = state == "suspended" ? now : nil
        if state == "active"
          dossier.archived_at = nil
          dossier.retention_until = nil
        end
        dossier.save!
      end

      def self.archived(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any, now : Time) : Nil
        return unless ok
        backup = record_backup(task, dossier, "archive", result["backup"]? || result, now)
        backup.frozen = true
        backup.keep_until = now.shift(years: Config::ARCHIVE_RETENTION_YEARS)
        backup.state = result["backup"]?.try(&.["verified"]?).try(&.as_bool?) ? "verified" : backup.state
        backup.verified_at = now if backup.state == "verified"
        backup.save!
        dossier.state = "archived"
        dossier.archived_at = now
        dossier.retention_until = now.shift(years: Config::ARCHIVE_RETENTION_YEARS)
        dossier.save!
      end

      def self.deleted(dossier : Dossier, ok : Bool, now : Time) : Nil
        return unless ok
        Backup.filter(dossier_id: dossier.pk).exclude(state: "pruned").update(state: "pruned", pruned_at: now)
        dossier.state = "deleted"
        dossier.deleted_at = now
        dossier.save!
      end

      def self.upgraded(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any, now : Time) : Nil
        if backup = result["backup"]?
          record_backup(task, dossier, "pre_upgrade", backup, now) if backup.as_h?
        end
        if ok
          dossier.version = result["version"]?.try(&.as_s?) || task.params_json["version"]?.try(&.as_s?) || dossier.version
          dossier.save!
        end
        if wave = task.wave
          Waves.advance(wave, now)
        end
      end

      def self.invited(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any) : Nil
        return unless ok
        if url = result["url"]?.try(&.as_s?)
          email = result["email"]?.try(&.as_s?) || task.params_json["email"]?.try(&.as_s?) || dossier.admin_email.to_s
          Mailer.invitation_to_dossier(dossier, email, url)
        end
      end

      def self.backed_up(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any, now : Time) : Nil
        kind = task.params_json["kind"]?.try(&.as_s?) || "manual"
        if ok
          record_backup(task, dossier, kind, result, now)
        else
          Backup.create!(dossier: dossier, task: task, kind: kind, state: "failed", taken_at: now)
        end
      end

      def self.pruned(task : Task, ok : Bool, now : Time) : Nil
        return unless ok
        ids = task.params_json["backup_ids"]?.try(&.as_a.map(&.as_i64)) || [] of Int64
        Backup.filter(id__in: ids, frozen: false).update(state: "pruned", pruned_at: now)
      end

      def self.test_restored(task : Task, ok : Bool, now : Time) : Nil
        id = task.params_json["backup_id"]?.try(&.as_i64?)
        return if id.nil?
        backup = Backup.filter(id: id).first
        return if backup.nil?
        if ok
          backup.test_restored_at = now
          backup.state = "verified"
          backup.verified_at = now
          backup.save!
        else
          Alerts.open("test_restore_failed", "danger", dossier: backup.dossier, detail: "backup #{id}", now: now)
        end
      end

      def self.restored(task : Task, dossier : Dossier, ok : Bool, result : JSON::Any, now : Time) : Nil
        if safety = result["safety_backup"]?
          record_backup(task, dossier, "pre_restore", safety, now) if safety.as_h?
        end
        return unless ok
        if task.params_json["target"]?.try(&.as_s?) == "new"
          slug = task.params_json["new_slug"]?.try(&.as_s?)
          if slug && (copy = Dossier.filter(slug: slug).first)
            copy.state = "active"
            copy.database = result["database"]?.try(&.as_s?) || copy.database
            copy.version = result["version"]?.try(&.as_s?) || copy.version
            copy.save!
          end
        else
          dossier.state = "active"
          dossier.version = result["version"]?.try(&.as_s?) || dossier.version
          dossier.save!
        end
      end

      def self.record_backup(task : Task, dossier : Dossier, kind : String, data : JSON::Any, now : Time) : Backup
        taken = data["taken_at"]?.try(&.as_s?).try { |value| Time.parse_rfc3339(value) rescue nil } || now
        Backup.create!(
          dossier: dossier, task: task, kind: kind, state: "done",
          path: data["path"]?.try(&.as_s?) || "",
          media_path: data["media_path"]?.try(&.as_s?) || "",
          size_bytes: data["size_bytes"]?.try(&.as_i64?),
          sha256: data["sha256"]?.try(&.as_s?) || "",
          version: data["version"]?.try(&.as_s?) || dossier.version.to_s,
          taken_at: taken,
          keep_until: taken + (dossier.backup_retention_days || 30).days,
        )
      end

      def self.record_certificate(dossier : Dossier, result : JSON::Any, now : Time) : Nil
        certificate = result["certificate"]?
        return if certificate.nil? || certificate["issued"]?.try(&.as_bool?) != true
        CertificateIssue.create!(dossier: dossier, host: dossier.host, domain: dossier.server.try(&.domain) || Config.domain,
          staging: certificate["staging"]?.try(&.as_bool?) || false, issued_at: now)
      end
    end
  end
end
