# SPDX-License-Identifier: AGPL-3.0-or-later

module AdminSpec
  # Navigateur de test : garde les cookies d'une requête à l'autre, envoie
  # les formulaires encodés comme un navigateur.
  class Browser
    FORM = "application/x-www-form-urlencoded"

    getter jar = {} of String => String
    getter headers = {} of String => String

    def initialize(locale : String = "fr", token : String? = nil)
      @headers["Accept-Language"] = locale
      @headers["Host"] = "127.0.0.1"
      @jar[PartiduoAdmin::BaseHandler::COOKIE] = token if token
    end

    def get(path : String, headers = {} of String => String) : Marten::HTTP::Response
      perform { |client| client.get(path, headers: @headers.merge(headers)) }
    end

    def post(path : String, data = {} of String => String | Array(String), headers = {} of String => String) : Marten::HTTP::Response
      body = URI::Params.build do |form|
        data.each do |key, value|
          value.is_a?(Array) ? value.each { |item| form.add(key, item) } : form.add(key, value)
        end
      end
      perform { |client| client.post(path, data: body, content_type: FORM, headers: @headers.merge(headers)) }
    end

    def cookie(name : String) : String?
      @jar[name]?
    end

    private def perform(& : Marten::Spec::Client -> Marten::HTTP::Response) : Marten::HTTP::Response
      client = Marten::Spec::Client.new
      @jar.each { |name, value| client.cookies[name] = value }
      response = yield client
      client.cookies.each do |(name, value)|
        value.empty? ? @jar.delete(name) : (@jar[name] = value)
      end
      response
    end
  end
end

class Marten::HTTP::Response
  def html : String
    HTML.unescape(content)
  end
end
