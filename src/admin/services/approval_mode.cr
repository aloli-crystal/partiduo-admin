# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Validation à deux *au choix* (décision du 29 septembre 2026,
  # D-VAL2-001 et suivantes). Chaque structure — cabinet, gestionnaire
  # indépendant, parc sans cabinet — règle si ses opérations sensibles
  # (suppression définitive, recours d'accès) exigent deux personnes :
  #
  # * `single` (une personne, défaut) : le demandeur confirme seul, après
  #   une authentification forte récente et une confirmation explicite ;
  # * `dual` (deux personnes) : une autre personne habilitée valide,
  #   comme avant.
  #
  # La validation à deux ne s'active qu'avec au moins deux personnes
  # habilitées ; si l'équipe retombe à une personne, elle se désactive
  # d'elle-même, trace au journal d'audit.
  module ApprovalMode
    alias Outcome = Fleet::Outcome

    SINGLE = "single"
    DUAL   = "dual"

    # Personnes habilitées d'une structure : celles qui peuvent valider une
    # opération sensible de ses dossiers, c'est-à-dire ses admins actifs ;
    # pour le parc sans cabinet, les super-admins actifs en plus.
    def self.team(firm : Firm) : Array(User)
      members = User.filter(firm_id: firm.pk, role: Config::FIRM_ADMIN, active: true).order("email").to_a
      if firm.fleet?
        members = User.filter(role: Config::SUPER_ADMIN, active: true).order("email").to_a + members
      end
      members
    end

    def self.team_size(firm : Firm) : Int32
      count = User.filter(firm_id: firm.pk, role: Config::FIRM_ADMIN, active: true).count
      count += User.filter(role: Config::SUPER_ADMIN, active: true).count if firm.fleet?
      count.to_i32
    end

    # Mode en vigueur pour les dossiers de la structure (après
    # réconciliation avec l'équipe).
    def self.mode(firm : Firm, now : Time = Config.now) : String
      reconcile(firm, now)
      firm.dual_approval ? DUAL : SINGLE
    end

    def self.mode_for(dossier : Dossier, now : Time = Config.now) : String
      mode(dossier.firm!, now)
    end

    # Qui règle : l'admin de la structure (cabinet, gestionnaire
    # indépendant) ; le super-admin pour le parc sans cabinet, son propre
    # périmètre. Le super-admin consulte les autres sans les changer.
    def self.can_manage?(user : User, firm : Firm) : Bool
      return user.super_admin? if firm.fleet?
      user.firm_admin? && user.active == true && user.firm_id == firm.pk
    end

    def self.can_view?(user : User, firm : Firm) : Bool
      user.super_admin? || can_manage?(user, firm)
    end

    # Proposée : cabinet de plusieurs personnes habilitées encore réglé sur
    # « une personne ». Une proposition, jamais une activation d'office.
    def self.suggested?(firm : Firm) : Bool
      firm.kind == "cabinet" && !firm.dual_approval && team_size(firm) >= 2
    end

    def self.set(user : User, firm : Firm, dual : Bool, now : Time = Config.now) : Outcome(Firm)
      return Outcome(Firm).failure("base", "admin.errors.forbidden") unless can_manage?(user, firm)
      reconcile(firm, now)
      return Outcome(Firm).new(firm) if firm.dual_approval == dual
      size = team_size(firm)
      return Outcome(Firm).failure("mode", "admin.errors.dual_approval.team") if dual && size < 2
      before = firm.approval_mode
      firm.dual_approval = dual
      firm.dual_approval_changed_at = now
      firm.save!
      pending = pending_count(firm, now)
      Audit.log(user, "dual_approval.change", target: firm,
        detail: {"before" => before, "after" => firm.approval_mode, "team" => size.to_s, "pending" => pending.to_s})
      Outcome(Firm).new(firm)
    end

    # Désactivation d'office si l'équipe ne compte plus deux personnes
    # habilitées (départ, compte désactivé) : mise à jour conditionnelle,
    # une seule trace même sous concurrence. Les demandes en attente le
    # restent ; le demandeur pourra les confirmer seul. Rend `true` si le
    # réglage vient d'être désactivé.
    def self.reconcile(firm : Firm, now : Time = Config.now) : Bool
      return false unless firm.dual_approval
      size = team_size(firm)
      return false if size >= 2
      changed = Firm.filter(id: firm.pk, dual_approval: true).update(dual_approval: false, dual_approval_changed_at: now)
      firm.dual_approval = false
      firm.dual_approval_changed_at = now
      return false unless changed == 1
      Audit.log(nil, "dual_approval.auto_off", target: firm,
        detail: {"before" => DUAL, "after" => SINGLE, "team" => size.to_s, "pending" => pending_count(firm, now).to_s},
        actor_label: "system")
      true
    end

    # Toutes les structures réglées sur « deux personnes » : planification
    # et changements d'équipe.
    def self.reconcile_all(now : Time = Config.now) : Int32
      Firm.filter(dual_approval: true).to_a.count { |firm| reconcile(firm, now) }
    end

    # Après un changement d'équipe (compte désactivé, super-admin retiré) :
    # la structure de l'utilisateur, et le parc sans cabinet pour un
    # super-admin.
    def self.after_team_change(user : User, now : Time = Config.now) : Nil
      if firm = user.firm
        reconcile(firm, now)
      end
      Firm.filter(kind: "fleet").each { |fleet| reconcile(fleet, now) } if user.super_admin?
    end

    def self.pending_count(firm : Firm, now : Time = Config.now) : Int32
      pending(firm, now).size
    end

    # Demandes en attente sur les dossiers de la structure.
    def self.pending(firm : Firm, now : Time = Config.now) : Array(Approval)
      ids = dossier_ids(firm)
      return [] of Approval if ids.empty?
      Approval.filter(state: "pending", expires_at__gt: now, dossier_id__in: ids).order("-id").to_a
    end

    private def self.dossier_ids(firm : Firm) : Array(Int64)
      Dossier.filter(firm_id: firm.pk).map(&.pk!.as(Int64))
    end
  end
end
