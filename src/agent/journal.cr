# SPDX-License-Identifier: AGPL-3.0-or-later

require "json"

module PartiduoAgent
  # État d'une tâche en cours, sur le disque du serveur : étapes faites et
  # valeurs retenues (horodatage d'une sauvegarde, lien d'invitation…). Une
  # tâche reprise après une coupure saute les étapes déjà faites (ADR-008 D4 :
  # tâches reprenables). Fichier en 0600, effacé quand la tâche réussit.
  class Journal
    getter path : String

    def initialize(dir : String, task_id : Int64)
      Dir.mkdir_p(dir)
      @path = File.join(dir, "task-#{task_id}.json")
      @done = [] of String
      @values = {} of String => String
      load
    end

    def done?(step : String) : Bool
      @done.includes?(step)
    end

    def done : Array(String)
      @done.dup
    end

    def mark(step : String) : Nil
      @done << step unless @done.includes?(step)
      save
    end

    def []?(key : String) : String?
      @values[key]?
    end

    def []=(key : String, value : String) : String
      @values[key] = value
      save
      value
    end

    def reset : Nil
      @done.clear
      @values.clear
      save
    end

    def clear : Nil
      File.delete(@path) if File.exists?(@path)
    end

    private def load : Nil
      return unless File.exists?(@path)
      data = JSON.parse(File.read(@path))
      @done = data["done"].as_a.map(&.as_s)
      data["values"].as_h.each { |key, value| @values[key] = value.as_s }
    rescue JSON::ParseException | KeyError | TypeCastError
      @done = [] of String
    end

    private def save : Nil
      File.write(@path, {"done" => @done, "values" => @values}.to_json, perm: 0o600)
    end
  end
end
