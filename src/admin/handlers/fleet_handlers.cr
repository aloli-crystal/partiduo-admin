# SPDX-License-Identifier: AGPL-3.0-or-later

module PartiduoAdmin
  class ApprovalsHandler < ScreenHandler
    def get
      approvals = Approvals.visible(user).order("-id").to_a.first(100)
      rows = approvals.map do |approval|
        pending = approval.state == "pending"
        {"approval" => approval, "can_decide" => pending && Access.can_approve?(user, approval),
         "can_withdraw" => pending && approval.requested_by_id == user.pk,
         "can_confirm" => pending && Approvals.can_confirm_alone?(user, approval)}
      end
      page("admin/approvals.html", {"rows" => rows})
    end
  end

  class ApprovalDecisionHandler < ScreenHandler
    def post
      approval = Approvals.visible(user).filter(id: id_param).first
      raise Access::Denied.new("approval") if approval.nil?
      if params["decision"].to_s == "approve"
        outcome = Approvals.approve(user, approval)
        if outcome.ok?
          flash["success"] = I18n.t("admin.approvals.approved")
        else
          flash["danger"] = outcome.errors.values.flatten.map { |key| I18n.t(key) }.join(" ")
        end
      else
        raise Access::Denied.new("approval") unless Approvals.reject(user, approval)
        flash["success"] = I18n.t("admin.approvals.rejected")
      end
      go("/approvals")
    end
  end

  class TasksHandler < ScreenHandler
    def get
      scope = Access.tasks(user).order("-id")
      state = query("state")
      scope = scope.filter(state: state) if Protocol::STATES.includes?(state)
      page("admin/tasks.html", {"tasks" => scope.to_a.first(200), "state" => state, "states" => Protocol::STATES.map { |code| {"code" => code, "key" => "admin.tasks.states.#{code}"} }})
    end
  end

  # Détail d'une tâche et son journal ; rafraîchi par HTMX tant qu'elle
  # n'est pas terminée.
  class TaskHandler < ScreenHandler
    def get
      task = Access.tasks(user).filter(id: id_param).first
      raise Access::Denied.new("task") if task.nil?
      template = htmx? ? "admin/_task_body.html" : "admin/task.html"
      page(template, {"task" => task, "result" => task.result.presence || "{}",
                      "can_retry" => Tasks.retryable?(task) && !user.file_manager?, "can_cancel" => task.state == "pending" && !user.file_manager?})
    end
  end

  class TaskCommandHandler < ScreenHandler
    def post
      require_admin!
      task = Access.tasks(user).filter(id: id_param).first
      raise Access::Denied.new("task") if task.nil?
      done = params["command"].to_s == "retry" ? Tasks.retry(user, task) : Tasks.cancel(user, task)
      flash[done ? "success" : "danger"] = I18n.t(done ? "admin.saved" : "admin.errors.task.state")
      go("/tasks/#{task.pk}")
    end
  end

  class AlertsHandler < ScreenHandler
    def get
      page("admin/alerts.html", {"alerts" => Alerts.visible(user).order("-opened_at").to_a, "quota" => LetsEncrypt.usage(Config.now)})
    end
  end

  class AuditHandler < ScreenHandler
    def get
      raise Access::Denied.new("audit") unless Access.can_view_audit?(user)
      scope = Access.audit(user).order("-id")
      action = query("action").strip
      scope = scope.filter(action__startswith: action) unless action.empty?
      page("admin/audit.html", {"entries" => scope.to_a.first(300), "action" => action})
    end
  end

  class ServersHandler < ScreenHandler
    def get
      require_fleet!
      page("admin/servers.html", {"servers" => Server.all.order("name").to_a, "name" => "", "hostname" => "",
                                  "domain" => Config.domain})
    end

    def post
      require_fleet!
      outcome = Directory.create_server(user, field("name"), field("hostname"), field("domain"))
      if outcome.ok?
        server, token = outcome.value!
        return page("admin/server_token.html", {"server" => server, "token" => token})
      end
      page("admin/servers.html", {"servers" => Server.all.order("name").to_a, "name" => field("name"),
                                  "hostname" => field("hostname"), "domain" => field("domain"), "errors" => translate(outcome.errors)}, status: 422)
    end
  end

  class ServerRotateHandler < ScreenHandler
    def post
      require_fleet!
      server = Server.get!(id: id_param)
      token = Directory.rotate_token(user, server) || raise Access::Denied.new("server")
      page("admin/server_token.html", {"server" => server, "token" => token})
    end
  end
end
