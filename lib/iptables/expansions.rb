require 'iptables/logger'

module IPTables
	class Macros
		attr_reader :named
		def initialize(expansion_hash)
			@expansion_hash = expansion_hash
			@named = {}
			@expansion_hash.each{ |name, info|
				@named[name] = Macro.new(name, info)
			}
		end
	end

	class Macro
		attr_reader :name, :children
		def initialize(name, info)
			@name = name
			@info = info
			@children = []

			case info
			when Array
				self.handle_array()
			when Hash
				self.handle_hash()
			when String
				self.handle_string()
			else
				raise "don't know how to handle info: #{info.inspect}"
			end
		end

		def add_child(rule_hash)
			@children.push(rule_hash)
		end

		def handle_array()
			@info.each{ |macro_hash|
				self.add_child(macro_hash)
			}
		end

		def handle_hash()
			self.add_child( @info )
		end

		def handle_string()
			self.add_child( {'raw' => @info} )
		end
	end

	class Services
		attr_reader :named
		def initialize(expansion_hash)
			@expansion_hash = expansion_hash
			@named = {}
			@expansion_hash.each{ |name, info|
				@named[name] = Service.new(name, info)
			}
		end
	end

	class Service
		attr_reader :name, :children
		def initialize(name, info)
			@name = name
			@info = info
			@children = []

			case info
			when Array
				self.handle_array()
			when Hash
				self.handle_hash()
			when Integer
				self.handle_integer()
			when String
				self.handle_string()
			else
				raise "don't know how to handle info: #{info.inspect}"
			end
		end

		def add_child(rule_hash)
			@children.push(rule_hash)
		end

		def handle_array()
			self.add_child( { 'comment' => "_ #{@name}" } )
			raise 'empty @info' if @info.empty?
			@info.each{ |service_info_hash|
				self.add_child(service_info_hash)
			}
		end

		def handle_hash()
			raise 'empty @info' if @info.empty?
			@info['service_name'] = @name
			self.add_child( @info )
		end

		def handle_integer()
			self.add_child( { 'comment' => "_ Port #{@info} - #{@name}" } )
			self.add_child({ 
				'raw' =>
				"-p tcp -m tcp --sport 1024:65535 --dport #{@info} -m state --state NEW,ESTABLISHED -j ACCEPT"
			})
		end

		def handle_string()
			self.add_child( { 'comment' => "_ #{@name}" } )
			self.add_child( {'raw' => @info} )
		end
	end

	class Interpolations
		# interpret strings such as "<% foo.bar %>" into equivalent primitives
		attr_reader :primitives, :named
		def initialize(primitives)
			@primitives = primitives
			$log.debug("interpolations primitives: #{@primitives}")
			@named = {}
		end

		def add(interpolation_string)
			@named[interpolation_string] = Interpolation.new(self, interpolation_string)
		end

		def children(interpolation_string)
			self.add(interpolation_string) unless @named.has_key? interpolation_string
			strings = @named[interpolation_string].children()
			returned_array = []
			case strings
			when Array
				strings.each{ |result|
					returned_array.push({'raw' => result})
				}
			else
				returned_array.push({'raw' => strings})
			end
			return returned_array
		end
	end

	class Interpolation
		@@interpolation_regex = /(.*?)<%\s*(\S+)\s*%>(.*)/

		def initialize(interpolations, initial_string)
			@interpolations = interpolations
			@initial_string = initial_string
			@child = nil
			if @initial_string =~ @@interpolation_regex:
				self.add_child($1, $2, $3)
			else
				$log.debug("completed substitution: #{@initial_string}")
			end
		end

		def add_child(first, identifier, last)
			interpolated = @interpolations.primitives.substitute(identifier)
			case interpolated
			when Array
				@child = []
				interpolated.each{ |value|
					@child.push(Interpolation.new(@interpolations, "#{first}#{value}#{last}"))
				}
			else
				@child = Interpolation.new(@interpolations, "#{first}#{interpolated}#{last}")
			end
		end

		def children()
			return_value = nil
			case @child
			when nil
				return_value = @initial_string
			when Array
				return_value = []
				@child.each{ |value|
					return_value.push(value.children())
				}
			else
				return_value = @child.children()
			end
			return return_value
		end
	end
end
