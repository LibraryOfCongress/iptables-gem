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

	def test_null_table_as_array
		test_iptables1 = IPTables::Tables.new( {
			'nat' => nil,
		})
		assert_equal(
			[], 
			test_iptables1.as_array,
			'null table should produce no policy and empty ruleset'
		)
	end

	def test_as_array_without_comments
		config = IPTables::Configuration.new()
		tables = IPTables::Tables.new({
			'filter' => {
				'INPUT' => {
					'policy' => 'ACCEPT',
					'rules' => [
						{ 'comment' => 'foobar' }
					]
				}
			}
		}, config)
		assert_equal(
			[
				"*filter",
				":INPUT ACCEPT",
				"COMMIT"
			], 
			tables.as_array(comments = false),
			'if comments are excluded, they should not appear in output'
		)
	end

	def test_ignore_comments_in_policy_fw
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
				'macro1' => [
					{ 'comment' => 'A comment in a macro' }
				]
			}) 
		)
		config.policy(
			IPTables::Tables.new({
				'filter' => {
					'INPUT' => {
						'policy' => 'ACCEPT',
						'rules' => [
							{ 'comment' => 'foobar' },
							'-j ACCEPT',
							{ 'node_addition_points' => [ 'INPUT' ] },
							{ 'macro' => 'macro1' },
							{ 'service' => 'service1' },
						]
					}
				}
			}, config)
		)
		config.rules(
			IPTables::Tables.new({
				'filter' => {
					'INPUT' => {
						'additions' => [
							{ 'comment' => 'a comment from an addition' },
							{ 
								'service_name' => 'a test service',
								'service_tcp' => 2222
							},
						]
					}
				}
			}, config)
		)
		converged_fw = config.converge_firewall
		assert_equal(
			[
				'*filter',
				':INPUT ACCEPT',
				'-A INPUT -j ACCEPT',
				'-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 2222 -m state --state NEW,ESTABLISHED -j ACCEPT',
				'-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 1111 -m state --state NEW,ESTABLISHED -j ACCEPT',
				'COMMIT'
			],
			converged_fw.as_array(false),
			'when excluding comments from a converged firewall, should see no comments'
		)
	end

	def test_two_tables_as_array
		test_iptables1 = IPTables::Tables.new( {
			'nat' => {
				'INPUT' => {
					'policy' => 'ACCEPT'
				}
			},
			'filter' => {
				'INPUT' => {
					'policy' => 'ACCEPT'
				}
			},
		})
		assert_equal(
			[
				"*filter",
				":INPUT ACCEPT",
				"COMMIT",
				"*nat",
				":INPUT ACCEPT",
				"COMMIT"
			], 
			test_iptables1.as_array,
			'two tables should produce consistent array output'
		)
	end

	def test_table_only_with_policy_as_array
		test_iptables1 = IPTables::Tables.new( {
			'nat' => {
				'INPUT' => {
					'policy' => 'ACCEPT'
				}
			},
		})
		assert_equal(
			[
				"*nat",
				":INPUT ACCEPT",
				"COMMIT"
			], 
			test_iptables1.as_array,
			'null table to array should produce an empty array'
		)
	end

	def test_merge_table_to_null_table
		test_iptables1 = IPTables::Tables.new( {
			'table1' => nil,
		})
		test_iptables2 = IPTables::Tables.new( {
			'table1' => {
				'INPUT' => {
					'policy' => 'ACCEPT'
				}
			},
		})
		test_iptables1.merge(test_iptables2)
		assert_kind_of(IPTables::Table, test_iptables1.tables['table1'], 'after merge, table1 should be a Table')
		assert_equal(
			[
				"*table1",
				":INPUT ACCEPT",
				"COMMIT"
			], 
			test_iptables1.as_array,
			'after merge, table1 should include a complete ruleset'
		)
	end

	def test_custom_service_additions
		config = IPTables::Configuration.new()
		policy_table = IPTables::Tables.new({
			'filter' => {
				'INPUT' => {
					'policy' => 'ACCEPT',
					'rules' => [
						{
							'node_addition_points' => [ 'INPUT' ]
						},
					]
				}
			}
		}, config)
		rules_table = IPTables::Tables.new({
			'filter' => {
				'INPUT' => {
					'additions' => [
						{
							'service_name' => 'svc1',
							'service_tcp' => 2222
						},
						{
							'service_name' => 'svc2',
							'service_udp' => 2223
						},
						{
							'service_name' => 'svc3',
							'service_tcp' => 2224,
							'service_udp' => 2225
						}
					]
				}
			}
		}, config)
		policy_table.merge(rules_table)
		assert_equal(
			[
				"*filter",
				":INPUT ACCEPT",
				'-A INPUT -m comment --comment "_ Port 2222 - svc1"',
				'-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 2222 -m state --state NEW,ESTABLISHED -j ACCEPT',
				'-A INPUT -m comment --comment "_ Port 2223 - svc2"',
				'-A INPUT -p udp -m udp --sport 1024:65535 --dport 2223 -m state --state NEW,ESTABLISHED -j ACCEPT',
				'-A INPUT -m comment --comment "_ svc3"',
				'-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 2224 -m state --state NEW,ESTABLISHED -j ACCEPT',
				'-A INPUT -p udp -m udp --sport 1024:65535 --dport 2225 -m state --state NEW,ESTABLISHED -j ACCEPT',
				"COMMIT"
			], 
			policy_table.as_array,
			'adding custom services on a node_addition_point should produce known results'
		)
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

#	def test_compare
#		test_iptables1 = IPTables::Tables.new(
#			<<-EOS.dedent
#				*table2
#				:INPUT DROP [0:0]
#				COMMIT
#				*table1
#				:INPUT DROP [0:0]
#				COMMIT
#				*table3
#				:INPUT DROP [0:0]
#				COMMIT
#			EOS
#		)
#		test_iptables2 = IPTables::Tables.new(
#			<<-EOS.dedent
#				*table4
#				:INPUT DROP [0:0]
#				COMMIT
#				*table3
#				:INPUT DROP [0:0]
#				-A INPUT -J ACCEPT
#				COMMIT
#				*table2
#				:INPUT DROP [0:0]
#				COMMIT
#			EOS
#		)
#
#		assert_raise( RuntimeError ) { test_iptables1.compare(nil) }
#
#		$log.level = Logger::DEBUG
#		comparison = test_iptables1.compare(test_iptables2)
#		$log.level = Logger::WARN
#		assert_equal(
#			{
#				"only_in_self"=>[
#					'*table1',
#					':INPUT DROP',
#					'COMMIT'
#				], 
#				"only_in_compared"=>[
#					'-A INPUT -J ACCEPT',
#					'*table4',
#					':INPUT DROP',
#					'COMMIT'
#				]
#			},
#			comparison,
#			'comparison should show all missing rules from first table, and extra rules in second table'
#		)
#	end

	def test_get_node_additions
		# not testing this directly here?
	end

	def test_parse
		assert_raise( RuntimeError ) { IPTables::Tables.new('garbage') }
		assert_raise( RuntimeError, 'should not allow empty iptables parsed rules' ) { IPTables::Tables.new('') }
	end
end

class TestTablesComparison < Test::Unit::TestCase
	def setup
		@iptables_text = 
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
				*table2
				:chain3 ACCEPT [0:0]
				-A chain3 -m comment --comment "comment3"
				-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
				-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
				:chain4 ACCEPT [0:0]
				-A chain4 -m comment --comment "comment4"
				-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT
				-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT
				COMMIT
			EOS
		@iptables1 = IPTables::Tables.new( @iptables_text )
	end

	def test_invalid
		assert_raise( RuntimeError, 'should require valid IPTables::Tables object as first parameter' ) { 
			IPTables::TablesComparison.new(nil, @iptables1)
		}
		assert_raise( RuntimeError, 'should require valid IPTables::Tables object as second parameter' ) { 
			IPTables::TablesComparison.new(@iptables1, nil)
		}
	end

	def test_equal
		iptables2 = IPTables::Tables.new( @iptables_text )
		comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

		assert_equal(
			true,
			comparison.equal?,
			'Set of tables with same contents should evaluate as equal.'
		)
	end

	def test_missing_table
		iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
			EOS
		)
		comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

		assert_equal(
			false,
			comparison.equal?,
			'Set of tables with one missing a table should evaluate as unequal.'
		)
	end

	def test_additional_table
		iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
				*table2
				:chain3 ACCEPT [0:0]
				-A chain3 -m comment --comment "comment3"
				-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
				-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
				:chain4 ACCEPT [0:0]
				-A chain4 -m comment --comment "comment4"
				-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT
				-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT
				COMMIT
				*table3
				:chain5 ACCEPT [0:0]
				-A chain5 -m comment --comment "comment5"
				-A chain5 -p tcp -m tcp --dport 9 -j ACCEPT
				-A chain5 -p tcp -m tcp --dport 10 -j ACCEPT
				:chain6 ACCEPT [0:0]
				-A chain6 -m comment --comment "comment6"
				-A chain6 -p tcp -m tcp --dport 11 -j ACCEPT
				-A chain6 -p tcp -m tcp --dport 12 -j ACCEPT
				COMMIT
			EOS
		)
		comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

		assert_equal(
			false,
			comparison.equal?,
			'Set of tables with one having an additional table should evaluate as unequal.'
		)
	end

	def test_differing_table
		iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
				*table2
				:chain3 ACCEPT [0:0]
				-A chain3 -m comment --comment "comment3"
				-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
				-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
				:chain4 ACCEPT [0:0]
				-A chain4 -m comment --comment "comment4"
				-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT
				-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT
				COMMIT
			EOS
		)
		comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

		assert_equal(
			false,
			comparison.equal?,
			'Set of tables with one having a differing rule should evaluate as unequal.'
		)
	end

	def test_differing_chain_comments
		iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "changed comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
				*table2
				:chain3 ACCEPT [0:0]
				-A chain3 -m comment --comment "comment3"
				-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
				-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
				:chain4 ACCEPT [0:0]
				-A chain4 -m comment --comment "comment4"
				-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT
				-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT
				COMMIT
			EOS
		)
		comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

		comparison.ignore_comments
		assert_equal(
			true,
			comparison.equal?,
			'Set of tables that differ only by comments should evaluate as equal when ignoring comments.'
		)

		comparison.include_comments
		assert_equal(
			false,
			comparison.equal?,
			'Set of tables that differ only by comments should evaluate as unequal when including comments.'
		)
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

class TestTableComparison < Test::Unit::TestCase
	def setup
		@test_iptables = 
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
			EOS
		@table1 = IPTables::Tables.new( @test_iptables ).tables['table1']
	end

	def test_invalid
		assert_raise( RuntimeError, 'should require valid IPTables::Table object as first parameter' ) { 
			IPTables::TableComparison.new(nil, @table1)
		}
		assert_raise( RuntimeError, 'should require valid IPTables::Table object as second parameter' ) { 
			IPTables::TableComparison.new(@table1, nil)
		}
	end

	def test_equal
		test_iptables2 = IPTables::Tables.new( @test_iptables )
		table2 = test_iptables2.tables['table1']
		comparison = IPTables::TableComparison.new(@table1, table2)

		assert_equal(
			true,
			comparison.equal?,
			'Tables with same chains should evaluate as equal.'
		)
	end

	def test_missing_chain
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				COMMIT
			EOS
		)
		table2 = test_iptables2.tables['table1']
		comparison = IPTables::TableComparison.new(@table1, table2)

		assert_equal(
			false,
			comparison.equal?,
			'Tables with missing chains should evaluate as unequal.'
		)
	end

	def test_additional_chain
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				:chain3 ACCEPT [0:0]
				-A chain3 -m comment --comment "comment3"
				-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
				-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
				COMMIT
			EOS
		)
		table2 = test_iptables2.tables['table1']
		comparison = IPTables::TableComparison.new(@table1, table2)

		assert_equal(
			false,
			comparison.equal?,
			'Tables with additional chains should evaluate as unequal.'
		)
	end

	def test_differing_chain
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
			EOS
		)
		table2 = test_iptables2.tables['table1']
		comparison = IPTables::TableComparison.new(@table1, table2)

		assert_equal(
			false,
			comparison.equal?,
			'Tables with additional chains should evaluate as unequal.'
		)
	end

	def test_differing_chain_comments
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				:chain2 ACCEPT [0:0]
				-A chain2 -m comment --comment "changed comment2"
				-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
				-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
				COMMIT
			EOS
		)
		table2 = test_iptables2.tables['table1']
		comparison = IPTables::TableComparison.new(@table1, table2)

		comparison.ignore_comments
		assert_equal(
			true,
			comparison.equal?,
			'Tables with chains that differ only by comments should evaluate as equal when ignoring comments.'
		)

		comparison.include_comments
		assert_equal(
			false,
			comparison.equal?,
			'Tables with chains that differ only by comments should evaluate as unequal when including comments.'
		)
	end
end

class TestChain < Test::Unit::TestCase
	def setup
		@test_iptables = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "BEGIN: in-bound traffic"
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
		assert_equal(
			[
				'-A chain1 -m comment --comment "BEGIN: in-bound traffic"',
				'-A chain1 -j ACCEPT'
			], 
			@chain1.as_array,
			'chain as array should produce known output'
		)
	end

	def test_as_array_without_comments
		assert_equal(
			@chain1.rules[0].type,
			'comment',
			'a chain rule that is known to be a comment should have type comment'
		)
		assert_equal(
			[ '-A chain1 -j ACCEPT' ], 
			@chain1.as_array(comments = false),
			'chain as array without comments should produce known output'
		)
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

class TestChainComparison < Test::Unit::TestCase
	def setup
		@iptables_text = 
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				COMMIT
			EOS
		@table1_chain = IPTables::Tables.new(@iptables_text).tables['table1'].chains['chain1']
	end

	def test_invalid
		assert_raise( RuntimeError, 'should require valid IPTables::Chain object as first parameter' ) { 
			IPTables::ChainComparison.new(nil, @table1_chain)
		}
		assert_raise( RuntimeError, 'should require valid IPTables::Chain object as second parameter' ) { 
			IPTables::ChainComparison.new(@table1_chain, nil)
		}
	end

	def test_equal
		test_iptables2 = IPTables::Tables.new(@iptables_text)
		table2_chain = test_iptables2.tables['table1'].chains['chain1']
		comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)

		assert_equal(
			true,
			comparison.equal?,
			'Chains with same rules and policies should evaluate as equal.'
		)
	end

	def test_unequal_comments
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "differing comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				COMMIT
			EOS
		)
		table2_chain = test_iptables2.tables['table1'].chains['chain1']
		comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)

		comparison.ignore_comments
		assert_equal(
			true,
			comparison.equal?,
			'When ignoring comments, chains with same rules/policies but differing comments should evaluate as equal.'
		)

		comparison.include_comments
		assert_equal(
			false,
			comparison.equal?,
			'When including comments, chains with same rules/policies but differing comments should evaluate as unequal.'
		)
		assert_equal(
			{0=>'-A chain1 -m comment --comment "comment1"'},
			comparison.missing,
			'When including comments, chains with same rules/policies but differing comments should have one missing rule.'
		)
		assert_equal(
			{0=>'-A chain1 -m comment --comment "differing comment1"'},
			comparison.new,
			'When including comments, chains with same rules/policies but differing comments should have one new rule.'
		)
	end

	def test_missing_rules
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				COMMIT
			EOS
		)
		table2_chain = test_iptables2.tables['table1'].chains['chain1']
		comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)

		assert_equal(
			{
				2=>"-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT"
			},
			comparison.missing,
			'Chains with missing rules should show this.'
		)
	end

	def test_additional_rules
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 ACCEPT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 12 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				COMMIT
			EOS
		)
		table2_chain = test_iptables2.tables['table1'].chains['chain1']
		comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)

		assert_equal(
			{
				2=>"-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT",
				3=>"-A chain1 -p tcp -m tcp --dport 12 -j ACCEPT"
			},
			comparison.new,
			'Chains with additional rules should show this.'
		)
	end

	def test_new_policy
		test_iptables2 = IPTables::Tables.new(
			<<-EOS.dedent
				*table1
				:chain1 REJECT [0:0]
				-A chain1 -m comment --comment "comment1"
				-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
				-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
				COMMIT
			EOS
		)
		table2_chain = test_iptables2.tables['table1'].chains['chain1']
		comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)

		assert_equal(
			true,
			comparison.new_policy?,
			'When compared, chains with new policy should show this.'
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
				"-A chain1 -m comment --comment \"_ Port 1337 - foo\"",
			 	"-A chain1 -p tcp -m tcp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT"
			],
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337}, @chain1 ).as_array
		)
		assert_equal(
			[
				"-A chain1 -m comment --comment \"_ Port 1337 - foo\"",
			 	"-A chain1 -p tcp -m tcp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT",
				"-A chain1 -p udp -m udp --sport 1024:65535 --dport 1337 -m state --state NEW,ESTABLISHED -j ACCEPT"
			],
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337, 'service_udp' => 1337}, @chain1 ).as_array
		)
		assert_raise( RuntimeError ) { 
			IPTables::Rule.new( {'service_name' => 'foo', 'service_tcp' => 1337, 'service_udp' => 1337, 'fake' => 1}, @chain1 ).as_array
		}
		assert_raise( RuntimeError ) { IPTables::Rule.new( {'bad' => 1}, @chain1 ) }
	end

	def test_handle_comment
		rule = IPTables::Rule.new( {'comment' => 'a comment'}, @chain1 )
		assert_equal( 
			{'comment' => 'a comment'}, 
			rule.rule_hash,
			'comment attributes should be handled as comments'
		)
		assert_equal( 
			rule.type,
			'comment',
			'comment attributes should have their type set as "comment"'
		)
	end

	def test_parse_comment
		rule = IPTables::Rule.new( '-m comment --comment "BEGIN: in-bound traffic"', @chain1 )
		assert_equal( 
			{'comment' => 'BEGIN: in-bound traffic'}, 
			rule.rule_hash,
			'parsed comments should have their rule_hash set properly'
		)
		assert_equal( 
			rule.type,
			'comment',
			'parsed comments should have their type set as "comment"'
		)
		assert_equal( 
			[], 
			rule.as_array(comments = false),
			'parsed comments should not display when displayed with comments turned off'
		)
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

	def test_handle_requires_primitive
		assert_equal( 
			[], 
			IPTables::Rule.new( 
				{
					'raw' => '-j ACCEPT', 
					'requires_primitive' => 'nonexistent'
				}, 
				@chain1 
			).as_array 
		)
		assert_equal( 
			['-A chain1 -j ACCEPT'], 
			IPTables::Rule.new( 
				{
					'raw' => '-j ACCEPT', 
					'requires_primitive' => 'leaf2'
				}, 
				@chain1 
			).as_array 
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
