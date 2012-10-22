require 'iptables/logger'

module IPTables
	class Primitives
		attr_reader :children
		def initialize(primitives_hash)
			@children = {}
			raise "expected Hash" unless primitives_hash.is_a? Hash
			primitives_hash.each{ |name, info|
				child = nil
				case info
				when Array, String
					child = info
				when Hash
					child = Primitives.new(info)
				else
					raise "unknown primitive type: #{name}"
				end

				self.instance_variable_set "@#{name}", child
				self.class.class_eval do
					define_method(name) { child }
				end
				@children[name] = child
			}
		end

		def substitute(identifier)
			components = identifier.split(/\./)
			the_first = components.first
			the_rest = components[1 .. -1].join('.')
			raise "failed to substitute unknown primitive: #{the_first}" unless @children.has_key? the_first
			case @children[the_first]
			when Primitives
				raise "failed to substitute partial primitive: #{the_first}" unless the_rest.any?
				return @children[the_first].substitute(the_rest)
			else
				return @children[the_first]
			end
		end

		def has_primitive?(identifier)
			begin
				self.substitute(identifier)
				return true
			rescue
				return false
			end
		end
	end
end
