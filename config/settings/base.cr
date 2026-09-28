# SPDX-License-Identifier: AGPL-3.0-or-later

Marten.configure do |config|
  config.secret_key = ENV["MARTEN_SECRET_KEY"]? || "__insecure_partiduo_admin_dev_only__"
  config.installed_apps = [PartiduoAdmin::App] of Marten::Apps::Config.class
  config.database do |db|
    db.from_url(PartiduoAdmin::Config.database_url)
  end
  config.i18n.default_locale = :fr
  config.i18n.available_locales = PartiduoAdmin::Config::LOCALES
  config.allowed_hosts = [PartiduoAdmin::Config.host, "127.0.0.1", "localhost"]

  config.middleware = [
    Marten::Middleware::Session,
    Marten::Middleware::Flash,
    Marten::Middleware::I18n,
    Marten::Middleware::GZip,
    Marten::Middleware::XFrameOptions,
    Marten::Middleware::XContentTypeOptions,
    Marten::Middleware::CrossOriginOpenerPolicy,
    Marten::Middleware::ReferrerPolicy,
  ] of Marten::Middleware.class

  config.templates.context_producers = [
    Marten::Template::ContextProducer::Request,
    Marten::Template::ContextProducer::Flash,
    Marten::Template::ContextProducer::Debug,
    Marten::Template::ContextProducer::I18n,
  ]
end
