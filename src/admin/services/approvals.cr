# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Double validation (ADR-008 D3, D5) : une personne demande, une *autre*
  # personne habilitée (admin du cabinet du dossier ou super-admin) valide ;
  # alors seulement la tâche est enregistrée, avec la référence et les deux
  # noms, reportés dans le journal de l'instance.
  module Approvals
    alias Outcome = Fleet::Outcome

    # Suppression définitive : seulement un dossier archivé dont la durée de
    # conservation légale (dix ans) est écoulée.
    def self.request_delete(user : User, dossier : Dossier, reason : String, now : Time = Config.now) : Outcome(Approval)
      return Outcome(Approval).failure("base", "admin.errors.forbidden") unless Access.can?(user, :request_delete, dossier)
      return Outcome(Approval).failure("base", "admin.errors.dossier.state") unless dossier.state == "archived"
      retention = dossier.retention_until
      if retention.nil? || retention > now
        return Outcome(Approval).failure("base", "admin.errors.dossier.retention_running")
      end
      create(user, dossier, "delete", reason, {} of String => String, now)
    end

    # Recours d'accès : réémission de l'invitation de l'administrateur du
    # dossier (ADR-008 D3), à l'adresse que désigne la société.
    def self.request_admin_invite(user : User, dossier : Dossier, email : String, reason : String,
                                  now : Time = Config.now) : Outcome(Approval)
      return Outcome(Approval).failure("base", "admin.errors.forbidden") unless Access.can?(user, :request_admin_invite, dossier)
      return Outcome(Approval).failure("base", "admin.errors.dossier.not_active") unless dossier.state == "active"
      return Outcome(Approval).failure("email", "admin.errors.email") unless Fleet::EMAIL.matches?(email.strip)
      create(user, dossier, "admin_invite", reason, {"email" => email.strip.downcase}, now)
    end

    private def self.create(user : User, dossier : Dossier, kind : String, reason : String,
                            params : Hash(String, String), now : Time) : Outcome(Approval)
      return Outcome(Approval).failure("reason", "admin.errors.required") if reason.strip.size < 5
      if Approval.filter(dossier_id: dossier.pk, kind: kind, state: "pending", expires_at__gt: now).exists?
        return Outcome(Approval).failure("base", "admin.errors.approval.already_pending")
      end
      approval = Approval.create!(kind: kind, reference: Secrets.reference("DV"), dossier: dossier,
        params: params.to_json, reason: reason.strip, requested_by: user, expires_at: now + Config::APPROVAL_TTL)
      Audit.log(user, "approval.request", target: approval, detail: {"kind" => kind, "dossier" => dossier.slug.to_s})
      Outcome(Approval).new(approval)
    end

    def self.approve(user : User, approval : Approval, now : Time = Config.now) : Outcome(Task)
      return Outcome(Task).failure("base", "admin.errors.approval.state") unless approval.state == "pending"
      if approval.expires_at! <= now
        approval.state = "expired"
        approval.save!
        return Outcome(Task).failure("base", "admin.errors.approval.expired")
      end
      if approval.requested_by_id == user.pk
        return Outcome(Task).failure("base", "admin.errors.approval.same_person")
      end
      return Outcome(Task).failure("base", "admin.errors.forbidden") unless Access.can_approve?(user, approval)
      dossier = approval.dossier!
      requester = approval.requested_by!
      params = Tasks.dossier_params(dossier)
      params["approval_ref"] = Tasks.any(approval.reference)
      params["approvers"] = Tasks.any([requester.email.to_s, user.email.to_s])
      params["reason"] = Tasks.any(approval.reason)
      kind = case approval.kind
             when "delete"
               # Recontrôle : l'état a pu changer depuis la demande.
               unless dossier.state == "archived" && (dossier.retention_until.try { |until_time| until_time <= now } || false)
                 return Outcome(Task).failure("base", "admin.errors.dossier.retention_running")
               end
               params["backups"] = Tasks.any(Backup.filter(dossier_id: dossier.pk).exclude(state: "pruned")
                 .flat_map { |backup| [backup.path.to_s, backup.media_path.to_s] }.reject(&.empty?))
               "instance.delete"
             else
               # Recontrôle : le dossier a pu être suspendu ou archivé depuis.
               return Outcome(Task).failure("base", "admin.errors.dossier.not_active") unless dossier.state == "active"
               params["email"] = Tasks.any(approval.param("email"))
               "instance.admin_invite"
             end
      # La demande passe à « validée » par une mise à jour conditionnelle,
      # dans la transaction qui enregistre la tâche : de deux validations
      # simultanées, une seule crée la tâche (D-AFN-010).
      task : Task? = nil
      Marten::DB::Connection.default.transaction do
        claimed = Approval.filter(id: approval.pk, state: "pending").update(state: "approved", decided_at: now)
        if claimed == 1
          created = Tasks.enqueue(kind, dossier.server!, params, user, dossier)
          approval.state = "approved"
          approval.decided_by = user
          approval.decided_at = now
          approval.task = created
          approval.save!
          task = created
        end
      end
      approved = task
      if approved.nil?
        approval.reload
        return Outcome(Task).failure("base", "admin.errors.approval.state")
      end
      Audit.log(user, "approval.approve", target: approval,
        detail: {"kind" => approval.kind.to_s, "requested_by" => requester.email.to_s, "dossier" => dossier.slug.to_s})
      Outcome(Task).new(approved)
    end

    def self.reject(user : User, approval : Approval, now : Time = Config.now) : Bool
      return false unless approval.state == "pending"
      return false unless approval.requested_by_id == user.pk || Access.can_approve?(user, approval)
      approval.state = "rejected"
      approval.decided_by = user
      approval.decided_at = now
      approval.save!
      Audit.log(user, "approval.reject", target: approval)
      true
    end

    # Demandes visibles : celles des dossiers de la portée de l'utilisateur.
    def self.visible(user : User) : Marten::DB::Query::Set(Approval)
      return Approval.all if user.super_admin?
      Approval.filter(dossier_id__in: Access.dossiers(user).map(&.pk!.as(Int64)))
    end
  end

  # Montée de version par vagues (ADR-008 D5) : `batch_size` dossiers à la
  # fois, chaque tâche avec sauvegarde préalable et retour arrière ; la vague
  # s'arrête au premier échec.
  module Waves
    alias Outcome = Fleet::Outcome

    def self.start(user : User, release : Release, batch_size : Int32, only : Array(Int64)? = nil,
                   now : Time = Config.now) : Outcome(Wave)
      return Outcome(Wave).failure("base", "admin.errors.forbidden") unless Access.fleet?(user)
      return Outcome(Wave).failure("batch_size", "admin.errors.invalid") unless (1..100).includes?(batch_size)
      dossiers = Dossier.filter(state: "active").exclude(version: release.version).order("id").to_a
      dossiers = dossiers.select { |dossier| only.includes?(dossier.pk) } if only
      return Outcome(Wave).failure("base", "admin.errors.wave.nothing") if dossiers.empty?
      wave = Wave.create!(release: release, batch_size: batch_size, requested_by_id: user.pk)
      Audit.log(user, "wave.start", target: wave, detail: {"dossiers" => dossiers.size.to_s, "batch" => batch_size.to_s})
      dossiers.each_with_index do |dossier, index|
        # Rang de lot : les tâches d'un lot ne partent qu'après le précédent.
        params = Tasks.dossier_params(dossier)
        params["from_version"] = Tasks.any(dossier.version)
        params["version"] = Tasks.any(release.version)
        params["wave_rank"] = Tasks.any(index // batch_size)
        Task.create!(kind: "instance.upgrade", server: dossier.server!, dossier: dossier, params: params.to_json,
          requested_by_id: user.pk, requested_by_label: user.email.to_s, wave: wave, wave_rank: index // batch_size,
          state: index < batch_size ? "pending" : "waiting")
      end
      Outcome(Wave).new(wave)
    end

    # Après chaque tâche de la vague : échec → vague arrêtée (tâches
    # restantes annulées) ; lot terminé → lot suivant libéré ; tout fait →
    # vague terminée.
    def self.advance(wave : Wave, now : Time = Config.now) : Nil
      return unless wave.state == "running"
      tasks = Task.filter(wave_id: wave.pk).to_a
      if tasks.any? { |task| task.state == "failed" }
        Task.filter(wave_id: wave.pk, state: "waiting").update(state: "cancelled", error: "wave_stopped", finished_at: now)
        wave.state = "failed"
        wave.finished_at = now
        wave.save!
        Alerts.open("wave_failed", "danger", detail: "wave #{wave.pk}", now: now)
        return
      end
      waiting = tasks.select { |task| task.state == "waiting" }
      active = tasks.select { |task| %w[pending running].includes?(task.state) }
      return unless active.empty?
      if waiting.empty?
        wave.state = "done"
        wave.finished_at = now
        wave.save!
        return
      end
      rank = waiting.min_of { |task| task.wave_rank || 0 }
      Task.filter(wave_id: wave.pk, state: "waiting", wave_rank: rank).update(state: "pending")
    end
  end
end
