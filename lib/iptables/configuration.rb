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

		def policy()
			@policy ||= nil
			return @policy unless @policy.nil?
			raise 'missing policy' unless @parsed_hash.has_key? 'policy'
			@policy = IPTables::Tables.new(@parsed_hash['policy'], self)
		end

		def policy6()
			@policy6 ||= nil
			return @policy6 unless @policy6.nil?
			raise 'missing policy6' unless @parsed_hash.has_key? 'policy6'
			@policy6 = IPTables::Tables.new(@parsed_hash['policy6'], self)
		end

		def interpolations()
			@interpolations ||= nil
			return @interpolations unless @interpolations.nil?
			@interpolations = IPTables::Interpolations.new(self.primitives)
		end

		def primitives()
			@primitives ||= nil
			return @primitives unless @primitives.nil?
			raise 'missing primitives' unless @parsed_hash.has_key? 'primitives'
			@primitives = IPTables::Primitives.new(@parsed_hash['primitives'])
		end

		def rules()
			@rules ||= nil
			return @rules unless @rules.nil?
			raise 'missing rules' unless @parsed_hash.has_key? 'rules'
			@rules = IPTables::Tables.new(@parsed_hash['rules'], self)
		end

		def services()
			@services ||= nil
			return @services unless @services.nil?
			raise 'missing services' unless @parsed_hash.has_key? 'services'
			@services = IPTables::Services.new(@parsed_hash['services'])
		end

		def macros()
			@macros ||= nil
			return @macros unless @macros.nil?
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
