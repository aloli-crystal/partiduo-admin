# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  # Chiffrement des sauvegardes d'un cabinet (D-CHF-001, D-CHF-002) : réglage
  # par défaut de ses dossiers, dépôt de sa clé publique (paire produite
  # dans le navigateur de l'admin du cabinet ou par `openssl`), dossiers qui
  # surchargent le réglage.
  class FirmBackupsHandler < ScreenHandler
    def get
      render_page(firm!)
    end

    def post
      firm = firm!
      outcome = BackupEncryption.set_firm_mode(user, firm, field("mode"))
      if outcome.ok?
        flash["success"] = I18n.t("admin.encryption.saved")
        return redirect("/firms/#{firm.pk}/backups")
      end
      render_page(firm, translate(outcome.errors), status: 422)
    end

    def firm! : Firm
      firm = Firm.filter(id: id_param).first
      raise Access::Denied.new("firm") if firm.nil? || !BackupEncryption.can_manage?(user, firm)
      firm
    end

    def render_page(firm : Firm, errors = {} of String => Array(String), public_key : String = "", status : Int32 = 200)
      modes = BackupEncryption::MODES.map do |mode|
        {"value" => mode, "key" => "admin.encryption.modes.#{mode}", "help" => "admin.encryption.help.#{mode}",
         "checked" => firm.backup_encryption == mode, "disabled" => mode == "cabinet" && firm.backup_key?.nil?}
      end
      dossiers = Dossier.filter(firm_id: firm.pk).exclude(state: "deleted").order("slug").to_a
      page("admin/firm_backups.html", {
        "firm"        => firm,
        "modes"       => modes,
        "errors"      => errors.empty? ? nil : errors,
        "mode_errors" => errs(errors, "mode"),
        "key_errors"  => errs(errors, "public_key"),
        "public_key"  => public_key,
        "can_deposit" => BackupEncryption.can_deposit_key?(user, firm),
        "dossiers"    => dossiers,
        "set_at"      => firm.backup_key_set_at.try(&.to_s("%Y-%m-%d %H:%M")),
      }, status: status)
    end
  end

  class FirmBackupKeyHandler < FirmBackupsHandler
    def get
      redirect("/firms/#{id_param}/backups")
    end

    def post
      firm = firm!
      outcome = BackupEncryption.deposit_key(user, firm, field("public_key"))
      if outcome.ok?
        flash["success"] = I18n.t("admin.encryption.deposited",
          fingerprint: BackupCrypto.display_fingerprint(firm.backup_key_fingerprint.to_s))
        return redirect("/firms/#{firm.pk}/backups")
      end
      raise Access::Denied.new("backup_key") if outcome.errors.has_key?("base")
      render_page(firm, translate(outcome.errors), field("public_key"), 422)
    end
  end

  # Surcharge du réglage pour un dossier (vide : celui du cabinet).
  class DossierEncryptionHandler < ScreenHandler
    def post
      dossier = dossier!
      outcome = BackupEncryption.set_dossier_mode(user, dossier, field("mode"))
      if outcome.ok?
        flash["success"] = I18n.t("admin.encryption.saved")
      else
        flash["danger"] = outcome.errors.values.flatten.map { |key| I18n.t(key) }.join(" ")
      end
      go("/dossiers/#{dossier.pk}")
    end
  end

  # Clé du cabinet requise (D-CHF-005) : la clé privée est lue et utilisée
  # *dans le navigateur* (`backup-keys.js`), qui déchiffre la clé de données
  # de cette sauvegarde et ne transmet qu'elle, avec la demande de
  # restauration ou de restauration test.
  class BackupUnlockHandler < ScreenHandler
    PURPOSES = %w[restore test]

    def get
      backup = Backup.filter(id: id_param).first
      raise Access::Denied.new("backup") if backup.nil? || !Access.in_scope?(user, backup.dossier!)
      dossier = backup.dossier!
      purpose = PURPOSES.includes?(query("purpose")) ? query("purpose") : "test"
      action = purpose == "restore" ? :restore : :test_restore
      raise Access::Denied.new("backup") unless Access.can?(user, action, dossier)
      unless backup.cabinet_sealed && %w[done verified].includes?(backup.state)
        flash["danger"] = I18n.t("admin.errors.backup.unusable")
        return redirect("/dossiers/#{dossier.pk}")
      end
      target = query("target") == "new" ? "new" : "replace"
      page("admin/backup_unlock.html", {
        "backup"      => backup,
        "dossier"     => dossier,
        "purpose"     => purpose,
        "purpose_key" => "admin.encryption.unlock.purposes.#{purpose}",
        "target"      => target,
        "target_key"  => "admin.restore.#{target}",
        "new_slug"    => query("new_slug"),
        "date"        => query("date").presence || backup.taken_at.try(&.to_s("%F")) || "",
        "fingerprint" => BackupCrypto.display_fingerprint(backup.key_fingerprint.to_s),
        "firm_key"    => backup.key_fingerprint == dossier.firm.try(&.backup_key_fingerprint),
        "is_restore"  => purpose == "restore",
      })
    end
  end
end
