require 'json'

module IPTables
  class Configuration
    @@json_pattern = /\.js(on)?$/

    def initialize(*args)
      @parsed_hash = {}
      self.parse_files(*args)
    end

    def parse_files(*args)
      args.each{ |arg|
        $log.debug("reading arg #{arg}")
        case arg
        when @@json_pattern
          handle_json(arg)
        else
          raise "don't know how to handle #{arg.inspect}"
        end
      }
    end

    def policy(in_policy = nil)
      @policy ||= nil
      return @policy unless @policy.nil?
      unless in_policy.nil?
        @policy = in_policy
        return @policy
      end
      raise 'missing policy' unless @parsed_hash.has_key? 'policy'
      @policy = IPTables::Tables.new(@parsed_hash['policy'], self)
    end

    def policy6(in_policy = nil)
      @policy6 ||= nil
      return @policy6 unless @policy6.nil?
      unless in_policy.nil?
        @policy6 = in_policy
        return @policy6
      end
      raise 'missing policy6' unless @parsed_hash.has_key? 'policy6'
      @policy6 = IPTables::Tables.new(@parsed_hash['policy6'], self)
    end

    def interpolations(in_interpolations = nil)
      @interpolations ||= nil
      return @interpolations unless @interpolations.nil?
      unless in_interpolations.nil?
        @interpolations = in_interpolations
        return @interpolations
      end
      @interpolations = IPTables::Interpolations.new(self.primitives)
    end

    def primitives(in_primitives = nil)
      @primitives ||= nil
      return @primitives unless @primitives.nil?
      unless in_primitives.nil?
        @primitives = in_primitives
        return @primitives
      end
      raise 'missing primitives' unless @parsed_hash.has_key? 'primitives'
      @primitives = IPTables::Primitives.new(@parsed_hash['primitives'])
    end

    def rules(in_rules = nil)
      @rules ||= nil
      return @rules unless @rules.nil?
      unless in_rules.nil?
        @rules = in_rules
        return @rules
      end
      raise 'missing rules' unless @parsed_hash.has_key? 'rules'
      @rules = IPTables::Tables.new(@parsed_hash['rules'], self)
    end

    def services(in_services = nil)
      @services ||= nil
      return @services unless @services.nil?
      unless in_services.nil?
        @services = in_services
        return @services
      end
      raise 'missing services' unless @parsed_hash.has_key? 'services'
      @services = IPTables::Services.new(@parsed_hash['services'])
    end

    def macros(in_macros = nil)
      @macros ||= nil
      return @macros unless @macros.nil?
      unless in_macros.nil?
        @macros = in_macros
        return @macros
      end
      raise 'missing macros' unless @parsed_hash.has_key? 'macros'
      @macros = IPTables::Macros.new(@parsed_hash['macros'])
    end

    def handle_json(file_name)
      json = File.read(file_name)
      JSON.parse(json).each{ |key, value|
        $log.debug("reading #{key} from file #{file_name}")
        raise "duplicate key: #{key}" if @parsed_hash.has_key? key
        @parsed_hash[key] = value
      }
    end

    def converge_firewall()
      policy_fw = self.policy
      rules_fw = self.rules
      policy_fw.merge(rules_fw)
      return policy_fw
    end
  end
end
