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

		# a huge merge test, because I am lazy
		config = IPTables::Configuration.new()
		policy_table = IPTables::Tables.new({
			'filter' => {
				'INPUT' => {
					'policy' => 'ACCEPT',
					'rules' => [
						'-J INPUT_rule1',
						{
							'node_addition_points' => [ 'INPUT', 'chain_INOUT' ]
						},
						'-J INPUT_rule3'
					]
				},
				'OUTPUT' => {
					'policy' => 'ACCEPT',
					'rules' => [
						'-J OUTPUT_rule1',
						{
							'node_addition_points' => [ 'OUTPUT', 'chain_INOUT' ]
						},
						'-J OUTPUT_rule3'
					]
				}
			}
		}, config)
		rules_table = IPTables::Tables.new({
			'filter' => {
				'INPUT' => {
					'policy' => 'DROP',
					'additions' => [
						'-J INPUT_addition'
					]
				},
				'FORWARD' => {
					'policy' => 'REJECT',
					'rules' => [
						'-J FORWARD_rule1'
					]
				},
				'chain_INOUT' => {
					'additions' => [
						'-J chain_INOUT_addition'
					]
				},
				'nonexistent' => {
					'additions' => [
						'-J nonexistent_addition'
					]
				}
			}
		}, config)
		policy_table.merge(rules_table)
		assert_equal(
			[
				"*filter",
				":INPUT DROP",
				":FORWARD REJECT",
				":OUTPUT ACCEPT",
				"-A INPUT -J INPUT_rule1",
				"-A INPUT -J INPUT_addition",
				"-A INPUT -J chain_INOUT_addition",
				"-A INPUT -J INPUT_rule3",
				"-A FORWARD -J FORWARD_rule1",
				"-A OUTPUT -J OUTPUT_rule1",
				"-A OUTPUT -J chain_INOUT_addition",
				"-A OUTPUT -J OUTPUT_rule3",
				"COMMIT"
			], 
			policy_table.as_array
		)
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
		# not testing this directly here?
	end

	def test_parse
		assert_raise( RuntimeError ) { IPTables::Tables.new('garbage') }
		assert_raise( RuntimeError, 'should not allow empty iptables parsed rules' ) { IPTables::Tables.new('') }
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

	def test_complete?
		assert(
			IPTables::Chain.new(
				'test_chain',
				{ 'rules' => [ '-j ACCEPT' ] }, 
				@test_iptables
			).complete?,
			'chain with rules should say it is complete'
		)
		assert(
			IPTables::Chain.new( 'test_chain', {}, @test_iptables).complete?,
			'chain without any rules or additions should say it is complete'
		)
		assert_equal(
			false,
			IPTables::Chain.new( 'test_chain', { 'additions' => [] }, @test_iptables).complete?,
			'chain with only additions should not say it is complete'
		)
	end
end

class TestRule < Test::Unit::TestCase
	def setup
		config = IPTables::Configuration.new
		config.primitives( 
			IPTables::Primitives.new({
				'branch' => { 'leaf1' => 'leaf1_value' },
				'leaf2' => 'leaf2_value',
			}) 
		)
		config.interpolations( 
			IPTables::Interpolations.new( config.primitives )
		)
		config.services( 
			IPTables::Services.new({
				'service1' => 1111,
			}) 
		)
		config.macros( 
			IPTables::Macros.new({
				'macro1' => '-j macro1',
			}) 
		)
		@test_iptables = IPTables::Tables.new({
			'table1' => {
				'chain1' => {
					'policy' => 'ACCEPT',
					'rules' => [
						'-j ACCEPT'
					]
				}
			}
		}, config)
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
		assert_raise( RuntimeError ) { IPTables::Rule.new( {'bad' => 1}, @chain1 ) }
	end

	def test_handle_node_addition_points
		rule = IPTables::Rule.new( {'node_addition_points' => ['chain1']}, @chain1 )
		assert_equal( [], rule.as_array )
	end

	def test_handle_interpolated
		assert_equal( 
			["-A chain1 -j leaf1_value"], 
			IPTables::Rule.new( {'interpolated' => '-j <% branch.leaf1 %>'}, @chain1 ).as_array 
		)
	end

	def test_handle_macro
		assert_equal( 
			["-A chain1 -j macro1"], 
			IPTables::Rule.new( {'macro' => 'macro1'}, @chain1 ).as_array 
		)
	end

	def test_handle_service
		assert_equal( 
			[
				"-A chain1 -m comment --comment \"_ Port 1111 - service1\"",
				"-A chain1 -p tcp -m tcp --sport 1024:65535 --dport 1111 -m state --state NEW,ESTABLISHED -j ACCEPT"
			], 
			IPTables::Rule.new( {'service' => 'service1'}, @chain1 ).as_array 
		)
	end

	def test_as_array
		assert_equal(
			["-A chain1 -p tcp -m limit --limit 1/sec --limit-burst 2 -j ULOG --ulog-prefix \"chain1:\""],
			IPTables::Rule.new( {'ulog' => '-p tcp'}, @chain1 ).as_array
		)
	end

	def test_path
		assert_equal('table1.chain1.0', @chain1.rules[0].path)
	end
end
