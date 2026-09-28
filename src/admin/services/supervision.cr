# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Quota Let's Encrypt du domaine (ADR-001 D2) : 50 certificats par semaine
  # glissante pour le domaine enregistré. Seuls les certificats de
  # production comptent (l'autorité de test est hors quota).
  module LetsEncrypt
    def self.issued_last_week(domain : String, now : Time = Config.now) : Int32
      CertificateIssue.filter(domain: domain, staging: false, issued_at__gt: now - 7.days).count.to_i32
    end

    def self.quota_reached?(domain : String, now : Time = Config.now) : Bool
      return false if domain.ends_with?(".localhost") || domain.ends_with?(".test")
      issued_last_week(domain, now) >= Config::LE_WEEKLY_LIMIT
    end

    record Usage, domain : String, issued : Int32, limit : Int32 do
      include Marten::Template::Object::Auto

      def percent : Int32
        (issued * 100 // limit).to_i32
      end

      def level : String
        issued >= Config::LE_WEEKLY_LIMIT ? "danger" : (issued >= Config::LE_WARNING ? "warning" : "success")
      end
    end

    def self.usage(now : Time = Config.now) : Array(Usage)
      domains = Server.filter(active: true).map(&.domain.to_s).uniq!
      domains.map { |domain| Usage.new(domain, issued_last_week(domain, now), Config::LE_WEEKLY_LIMIT) }
    end
  end

  # Alertes (ADR-008 D5) : une alerte ouverte par sujet et type, résolue
  # quand la condition disparaît ; envoyée par courriel à l'ouverture.
  module Alerts
    def self.open(kind : String, severity : String, dossier : Dossier? = nil, server : Server? = nil,
                  detail : String = "", now : Time = Config.now) : Alert
      scope = Alert.filter(kind: kind, resolved_at__isnull: true)
      scope = dossier ? scope.filter(dossier_id: dossier.pk) : scope.filter(dossier_id__isnull: true)
      scope = server ? scope.filter(server_id: server.pk) : scope.filter(server_id__isnull: true)
      if existing = scope.first
        return existing
      end
      alert = Alert.create!(kind: kind, severity: severity, dossier: dossier, server: server, detail: detail[0, 255]? || "", opened_at: now)
      Mailer.alert(alert)
      alert.notified_at = now
      alert.save!
      alert
    end

    def self.resolve(kind : String, dossier : Dossier? = nil, server : Server? = nil, now : Time = Config.now) : Nil
      scope = Alert.filter(kind: kind, resolved_at__isnull: true)
      scope = scope.filter(dossier_id: dossier.pk) if dossier
      scope = scope.filter(server_id: server.pk) if server
      scope.update(resolved_at: now)
    end

    def self.set(condition : Bool, kind : String, severity : String, dossier : Dossier? = nil, server : Server? = nil,
                 detail : String = "", now : Time = Config.now) : Nil
      condition ? open(kind, severity, dossier, server, detail, now) : resolve(kind, dossier, server, now)
    end

    def self.visible(user : User) : Marten::DB::Query::Set(Alert)
      scope = Alert.filter(resolved_at__isnull: true)
      return scope if user.super_admin?
      scope.filter(dossier_id__in: Access.dossiers(user).map(&.pk!.as(Int64)))
    end
  end

  # Supervision (ADR-008 D5) : état de chaque dossier (service, base,
  # certificat et échéance), disque du serveur, dernière sauvegarde, quota
  # Let's Encrypt ; relevés par la tâche `supervision.check`.
  module Supervision
    def self.params_for(server : Server) : Tasks::Params
      dossiers = Dossier.filter(server_id: server.pk, state__in: %w[active suspended]).order("slug").map do |dossier|
        {"slug" => dossier.slug.to_s, "host" => dossier.host, "database" => dossier.database.to_s,
         "expected" => dossier.state == "active" ? "running" : "stopped"}
      end
      {"dossiers" => Tasks.any(dossiers)}
    end

    def self.enqueue(server : Server) : Task
      Tasks.enqueue("supervision.check", server, params_for(server))
    end

    def self.apply(server : Server, success : Bool, result : JSON::Any, now : Time) : Nil
      return unless success
      if disk = result["disk"]?
        apply_disk(server, disk, now)
      end
      (result["dossiers"]?.try(&.as_a?) || [] of JSON::Any).each do |entry|
        dossier = Dossier.filter(slug: entry["slug"]?.try(&.as_s?).to_s, server_id: server.pk).first
        apply_dossier(dossier, entry, now) if dossier
      end
    end

    private def self.apply_disk(server : Server, disk : JSON::Any, now : Time) : Nil
      server.disk_total_bytes = disk["total_bytes"]?.try(&.as_i64?)
      server.disk_free_bytes = disk["free_bytes"]?.try(&.as_i64?)
      server.save!
      ratio = server.disk_free_ratio
      Alerts.set(!ratio.nil? && ratio < Config::DISK_WARNING_RATIO, "disk_low", "danger", server: server,
        detail: server.disk_free_percent, now: now)
    end

    private def self.apply_dossier(dossier : Dossier, entry : JSON::Any, now : Time) : Nil
      dossier.service_state = entry["service"]?.try(&.as_s?) || ""
      dossier.database_state = entry["database"]?.try(&.as_s?) || ""
      dossier.cert_expires_at = entry["cert_expires_at"]?.try(&.as_s?).try { |value| Time.parse_rfc3339(value) rescue nil }
      version = entry["version"]?.try(&.as_s?) || ""
      dossier.version = version unless version.empty?
      dossier.health_checked_at = now
      dossier.save!
      active = dossier.state == "active"
      Alerts.set(dossier.service_state != (active ? "running" : "stopped"), "service", "danger", dossier: dossier,
        detail: dossier.service_state.to_s, now: now)
      Alerts.set(active && dossier.database_state != "ok", "database", "danger", dossier: dossier,
        detail: dossier.database_state.to_s, now: now)
      cert = dossier.cert_expires_at
      Alerts.set(!cert.nil? && cert < now + Config::CERT_WARNING_DAYS.days, "certificate", "warning", dossier: dossier,
        detail: cert.try(&.to_s("%F")) || "", now: now)
    end

    # Contrôles tenus par l'administration elle-même : dernière sauvegarde,
    # quota Let's Encrypt, exécutant silencieux.
    def self.evaluate(now : Time = Config.now) : Nil
      Dossier.filter(state: "active").exclude(backup_schedule: "none").each do |dossier|
        last = dossier.last_backup_at
        reference = last || dossier.created_at!
        Alerts.set(reference < now - Config::BACKUP_WARNING_AGE, "backup_age", "warning", dossier: dossier,
          detail: last.try(&.to_s("%F %H:%M")) || "", now: now)
      end
      LetsEncrypt.usage(now).each do |usage|
        Alerts.set(usage.issued >= Config::LE_WARNING, "le_quota", usage.level, detail: "#{usage.domain} #{usage.issued}/#{usage.limit}", now: now)
      end
      Server.filter(active: true).each do |server|
        seen = server.last_seen_at
        Alerts.set(seen.nil? || seen < now - Config::AGENT_SILENCE_ALERT, "agent_silent", "danger", server: server,
          detail: seen.try(&.to_s("%F %H:%M")) || "", now: now)
      end
    end
  end

  # Planification (commande `manage schedule`, lancée par un minuteur
  # systemd) : sauvegardes planifiées, élagage selon la rétention,
  # restaurations test périodiques, supervision, alertes.
  module Scheduler
    record Summary, backups : Int32, prunes : Int32, test_restores : Int32, checks : Int32

    def self.run(now : Time = Config.now) : Summary
      backups = prunes = tests = checks = 0
      Dossier.filter(state: "active").exclude(backup_schedule: "none").each do |dossier|
        interval = dossier.backup_schedule == "weekly" ? 7.days : 1.day
        last = Backup.filter(dossier_id: dossier.pk, kind: "scheduled").exclude(state: "failed").order("-taken_at").first
        pending = Task.filter(dossier_id: dossier.pk, kind: "backup.run", state__in: %w[pending running]).exists?
        if !pending && (last.nil? || (last.taken_at || last.created_at!) <= now - interval + 1.hour)
          Fleet.backup_now(nil, dossier, "scheduled")
          backups += 1
        end
      end
      Dossier.filter(state__in: %w[active suspended]).each do |dossier|
        expired = Backup.filter(dossier_id: dossier.pk, frozen: false, state__in: %w[done verified failed], keep_until__lt: now).to_a
        # La dernière sauvegarde réussie n'est jamais élaguée.
        if latest = dossier.last_backup
          expired.reject! { |backup| backup.pk == latest.pk }
        end
        unless expired.empty?
          params = Tasks.dossier_params(dossier)
          params["backup_ids"] = Tasks.any(expired.map(&.pk!.as(Int64)))
          params["paths"] = Tasks.any(expired.flat_map { |backup| [backup.path.to_s, backup.media_path.to_s] }.reject(&.empty?))
          Tasks.enqueue("backup.prune", dossier.server!, params, nil, dossier)
          prunes += 1
        end
        latest = dossier.last_backup
        tested = Backup.filter(dossier_id: dossier.pk, test_restored_at__gt: now - (dossier.test_restore_days || 30).days).exists?
        if latest && !tested && !Task.filter(dossier_id: dossier.pk, kind: "backup.test_restore", state__in: %w[pending running]).exists?
          Fleet.test_restore(nil, latest)
          tests += 1
        end
      end
      Server.filter(active: true).each do |server|
        Supervision.enqueue(server)
        checks += 1
      end
      Supervision.evaluate(now)
      Approval.filter(state: "pending", expires_at__lte: now).update(state: "expired")
      Summary.new(backups, prunes, tests, checks)
    end
  end
end
