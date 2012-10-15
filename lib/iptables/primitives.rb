require 'iptables/logger'

module IPTables
	class Primitives
		attr_reader :children
		def initialize(primitives_hash)
			@children = {}
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
			raise "unknown primitive: #{the_first}" unless @children.has_key? the_first
			case @children[the_first]
			when Primitives
				return @children[the_first].substitute(the_rest)
			else
				return @children[the_first]
			end
		end
	end
end
