require 'common'

# inspired by https://github.com/cespare/ruby-dedent
class String
	def dedent
		lines = split "\n"
		return self if lines.empty?
		# first indented line determines indent level
		indentation = nil
		lines.each{ |line|
			next unless line =~ /^(\s+)/
			indentation = $1
			break
		}
		return self if indentation.nil?
		lines.map { |line| line.sub(/^#{indentation}/, "") }.join "\n"
	end
end

class TestTables < Test::Unit::TestCase
	def test_initialize
		assert_raise( RuntimeError ) { IPTables::Tables.new(1) }

		test_iptables = IPTables::Tables.new({
			'table1' => {},
			'table2' => nil
		})
		assert_kind_of(IPTables::Table, test_iptables.tables['table1'])
		assert_nil(test_iptables.tables['table2'])

		assert_equal({}, IPTables::Tables.new('').tables)
	end

	def test_as_array
		test_iptables = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				COMMIT
			EOS
		)
		assert_equal(['*table1', 'COMMIT'], test_iptables.as_array)
	end

	def test_merge
		test_iptables1 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				*table2
				COMMIT
			EOS
		)
		test_iptables2 = IPTables::Tables.new( {
			'table1' => {},
			'table2' => false,
			'table3' => nil,
			'table4' => {}
		})
		test_iptables1.merge(test_iptables2)
		assert_kind_of(IPTables::Table, test_iptables1.tables['table1'], 'after merge, table1 should still be a Table')
		assert_nil(test_iptables1.tables['table2'], 'after merge, should have no table2')
		assert_nil(test_iptables1.tables['table3'], 'after merge, should still have no table3')
		assert_kind_of(IPTables::Table, test_iptables1.tables['table4'], 'after merge, table4 should be a new Table')
	end

	def test_compare
		test_iptables1 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				COMMIT
			EOS
		)
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table2
				COMMIT
			EOS
		)

		assert_raise( RuntimeError ) { test_iptables1.compare(nil) }

		assert_equal(
			test_iptables1.compare(test_iptables2), 
			{"only_in_self"=>["*table1"], "only_in_compared"=>["*table2"]}
		)
	end

	def test_get_node_additions
		# not testing this directly, here?
		#test_iptables = IPTables::Tables.new({
		#	'table1' => {
		#		'INPUT' => {
		#			'rules' => [
		#				{ 'node_addition_points' => [ 'INPUT' ] }
		#			]
		#		}
		#	}
		#})
		#node_additions = test_iptables.get_node_additions('table1', 'INPUT')
	end

	def test_parse
		assert_raise( RuntimeError ) { IPTables::Tables.new('garbage') }
	end
end

class TestTable < Test::Unit::TestCase
	def test_initialize
		test_iptables = IPTables::Tables.new({
			'table1' => {
				'INPUT' => {
					'rules' => [
						'-j ACCEPT'
					]
				}
			}
		})
		table1 = test_iptables.tables['table1']
		assert_kind_of(IPTables::Tables, table1.my_iptables)
		assert_kind_of(IPTables::Chain, table1.chains['INPUT'])
		assert_equal('table1', table1.name)

		assert_raise( RuntimeError ) {  
			IPTables::Tables.new({
				'table1' => {
					'INPUT' => 1
				}
			})
		}
	end

	def test_path
		test_iptables = IPTables::Tables.new({
			'table1' => {
				'INPUT' => {
					'rules' => [
						'-j ACCEPT'
					]
				}
			}
		})
		table1 = test_iptables.tables['table1']
		assert_equal('table1', table1.path)
	end

	def test_merge
		test_iptables1 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				:chain2 ACCEPT [0:0]
				-A chain1 -j ACCEPT
				-A chain2 -j ACCEPT
				COMMIT
			EOS
		)
		table1 = test_iptables1.tables['table1']

		test_iptables2 = IPTables::Tables.new({
			'table1' => {
				'chain1' => {},
				'chain2' => false,
				'chain3' => nil,
				'chain4' => {},
			}
		})
		table2 = test_iptables2.tables['table1']

		table1.merge(table2)
		assert_kind_of(IPTables::Chain, table1.chains['chain1'])
		assert_nil(table1.chains['chain2'], 'after merge, should have no chain2')
		assert_nil(table1.chains['chain3'], 'after merge, should have no chain3')
		assert_kind_of(IPTables::Chain, table1.chains['chain4'])
	end
end

class TestChain < Test::Unit::TestCase
	def setup
		@test_iptables = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -j ACCEPT
				COMMIT
			EOS
		)
		@chain1 = @test_iptables.tables['table1'].chains['chain1']
	end

	def test_output_policy
		assert_equal('ACCEPT', @chain1.output_policy)
	end

	def test_as_array
		assert_equal(["-A chain1 -j ACCEPT"], @chain1.as_array)
	end

	def test_path
		assert_equal('table1.chain1', @chain1.path)
	end
end

class TestRule < Test::Unit::TestCase
	def setup
		@test_iptables = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -j ACCEPT
				COMMIT
			EOS
		)
		@chain1 = @test_iptables.tables['table1'].chains['chain1']
	end

	def test_initialize
		assert_raise( RuntimeError ) { IPTables::Rule.new( 1, @chain1 ) }
		assert_equal(0, @chain1.rules[0].position)
		assert_equal(
			["-A chain1 -j ACCEPT"], 
			IPTables::Rule.new( {'raw' => '-j ACCEPT'}, @chain1 ).as_array
		)
		assert_equal(
			[
				"-A chain1 -m comment --comment \"_ foo\"",
			 	"-A chain1 -p tcp -m tcp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT"
			],
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337}, @chain1 ).as_array
		)
		assert_equal(
			[
				"-A chain1 -m comment --comment \"_ foo\"",
			 	"-A chain1 -p tcp -m tcp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT",
				"-A chain1 -p udp -m udp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT"
			],
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337, 'service_udp' => 1337}, @chain1 ).as_array
		)
		assert_raise( RuntimeError ) { 
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337, 'service_udp' => 1337, 'fake' => 1}, @chain1 ).as_array
		}
		#rule1 = test_iptables.tables['table1'].chains['chain1'].rules[0]
	end
end
