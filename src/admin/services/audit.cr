# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAdmin
  # Journal d'audit nominatif en ajout seul (ADR-008 D2). Toute action de
  # l'administration y passe ; un déclencheur refuse modification et
  # suppression.
  module Audit
    def self.log(actor : User?, action : String, target : Marten::Model? = nil, detail = {} of String => String,
                 outcome : String = "ok", ip : String = "", firm_id : Int64? = nil,
                 actor_label : String? = nil) : AuditEntry
      target_type, target_id, target_label, target_firm = describe(target)
      AuditEntry.create!(
        actor_id: actor.try(&.pk),
        actor_label: actor_label || actor.try(&.email.to_s) || "",
        action: action,
        target_type: target_type,
        target_id: target_id,
        target_label: target_label[0, 255]? || "",
        firm_id: firm_id || target_firm || actor.try(&.firm_id),
        outcome: outcome,
        ip: ip[0, 64]? || "",
        detail: detail.to_json,
      )
    end

    private def self.describe(target : Marten::Model?) : {String, Int64?, String, Int64?}
      id = target.try(&.pk).as?(Int64)
      case target
      when Dossier  then {"dossier", id, target.slug.to_s, target.firm_id.as?(Int64)}
      when User     then {"user", id, target.email.to_s, target.firm_id.as?(Int64)}
      when Firm     then {"firm", id, target.name.to_s, id}
      when Payer    then {"payer", id, target.name.to_s, target.firm_id.as?(Int64)}
      when Server   then {"server", id, target.name.to_s, nil}
      when Release  then {"release", id, target.version.to_s, nil}
      when Task     then {"task", id, target.kind.to_s, target.dossier.try(&.firm_id).as?(Int64)}
      when Wave     then {"wave", id, target.release.try(&.version).to_s, nil}
      when Approval then {"approval", id, target.reference.to_s, target.dossier.try(&.firm_id).as?(Int64)}
      else               {"", nil, "", nil}
      end
    end
  end
end
