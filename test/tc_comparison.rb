require 'common'

class TestTablesComparison < Test::Unit::TestCase
  def setup
    @iptables_table1 = 
      <<-EOS.dedent
        *table1
        :chain1 ACCEPT [0:0]
        :chain2 ACCEPT [0:0]
        -A chain1 -m comment --comment "comment1"
        -A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
        -A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
        -A chain2 -m comment --comment "comment2"
        -A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
        -A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
        COMMIT
      EOS
    @iptables_text = 
      "#{@iptables_table1}\n"+
      <<-EOS.dedent
        *table2
        :chain3 ACCEPT [0:0]
        :chain4 ACCEPT [0:0]
        -A chain3 -m comment --comment "comment3"
        -A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
        -A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
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

    assert(
      comparison.equal?,
      'Set of tables with same contents should evaluate as equal.'
    )
    assert_equal(
      [],
      comparison.as_array,
      'Array output of tables with same contents should evaluate as empty.'
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
    assert_equal(
      comparison.as_array,
      [
        "Missing table: table2",
        ":chain3 ACCEPT",
        ":chain4 ACCEPT",
        "-A chain3 -m comment --comment \"comment3\"",
        "-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT",
        "-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT",
        "-A chain4 -m comment --comment \"comment4\"",
        "-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT",
        "-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT"
      ],
      'Array output of tables with one missing a table should evaluate to known values.'
    )
  end

  def test_nil_existing_policy_table
    iptables2 = IPTables::Tables.new({
      'table1' => {
        'chain1' => {
          'policy' => 'ACCEPT',
          'rules' => [
            '-m comment --comment "comment1"',
            '-p tcp -m tcp --dport 1 -j ACCEPT',
            '-p tcp -m tcp --dport 2 -j ACCEPT',
          ]
        },
        'chain2' => {
          'policy' => 'ACCEPT',
          'rules' => [
            '-m comment --comment "comment2"',
            '-p tcp -m tcp --dport 3 -j ACCEPT',
            '-p tcp -m tcp --dport 4 -j ACCEPT',
          ]
        },
      },
      'table2' => nil
    })
    comparison = IPTables::TablesComparison.new(@iptables1, iptables2)

    assert(
      comparison.equal?,
      'Set of tables which match except one is nil and one is a table should evaluate as equal.'
    )
    assert_equal(
      [],
      comparison.as_array,
      'Array output of tables which match except one one is nil and one is a table should evaluate as empty.'
    )
  end

  def test_nil_missing_policy_table
    iptables1 = IPTables::Tables.new( @iptables_table1 )
    iptables2 = IPTables::Tables.new({
      'table1' => {
        'chain1' => {
          'policy' => 'ACCEPT',
          'rules' => [
            '-m comment --comment "comment1"',
            '-p tcp -m tcp --dport 1 -j ACCEPT',
            '-p tcp -m tcp --dport 2 -j ACCEPT',
          ]
        },
        'chain2' => {
          'policy' => 'ACCEPT',
          'rules' => [
            '-m comment --comment "comment2"',
            '-p tcp -m tcp --dport 3 -j ACCEPT',
            '-p tcp -m tcp --dport 4 -j ACCEPT',
          ]
        },
      },
      'table2' => nil
    })
    comparison = IPTables::TablesComparison.new(iptables1, iptables2)

    assert(
      comparison.equal?,
      'Set of tables which match except one is nil and one is missing should evaluate as equal.'
    )
    assert_equal(
      [],
      comparison.as_array,
      'Array output of tables which match except one is nil and one is missing should evaluate as empty.'
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
    assert_equal(
      comparison.as_array,
      [
        "New table: table3",
        ":chain5 ACCEPT",
        ":chain6 ACCEPT",
        "-A chain5 -m comment --comment \"comment5\"",
        "-A chain5 -p tcp -m tcp --dport 9 -j ACCEPT",
        "-A chain5 -p tcp -m tcp --dport 10 -j ACCEPT",
        "-A chain6 -m comment --comment \"comment6\"",
        "-A chain6 -p tcp -m tcp --dport 11 -j ACCEPT",
        "-A chain6 -p tcp -m tcp --dport 12 -j ACCEPT"
      ],
      'Array output of tables with one having an additional table should evaluate to known values.'
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
    assert_equal(
      comparison.as_array,
      [
        "Changed table: table1",
        "Changed chain: chain1",
        "-1: -A chain1 -p tcp -m tcp --dport 1 -j ACCEPT",
        "+1: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT"
      ],
      'Array output of tables with one having a differing rule should evaluate to known values.'
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
    assert(
      comparison.equal?,
      'Set of tables that differ only by comments should evaluate as equal when ignoring comments.'
    )
    assert_equal(
      comparison.as_array,
      [], 
      'Array output of tables that differ only by comments should evaluate as empty when ignoring comments.'
    )

    comparison.include_comments
    assert_equal(
      false,
      comparison.equal?,
      'Set of tables that differ only by comments should evaluate as unequal when including comments.'
    )
    assert_equal(
      comparison.as_array,
      [
        "Changed table: table1",
        "Changed chain: chain1",
        "-0: -A chain1 -m comment --comment \"comment1\"",
        "+0: -A chain1 -m comment --comment \"changed comment1\""
      ],
      'Array output of tables that differ only by comments should evaluate to known values when ignoring comments.'
    )
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

    assert(
      comparison.equal?,
      'Tables with same chains should evaluate as equal.'
    )

    assert_equal(
      [],
      comparison.as_array,
      'When compared as array, tables with identical chains should return empty array.'
    )
  end

  def test_unequal_name
    test_iptables2 = IPTables::Tables.new(
      <<-EOS.dedent
        *table2
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
    table2 = test_iptables2.tables['table2']
    assert_raise( RuntimeError, 'compared table names should match' ) { 
      IPTables::TableComparison.new(@table1, table2)
    }
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

    assert_equal(
      [ 'chain2' ],
      comparison.missing,
      'Two compared tables with one chain missing should show this.'
    )

    assert_equal(
      [ 
        'Changed table: table1',
        'Missing chain:',
        ':chain2 ACCEPT',
        '-A chain2 -m comment --comment "comment2"',
        '-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT',
        '-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT'
      ],
      comparison.as_array,
      'When compared as array, two compared tables with one chain missing should show this.'
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

    assert_equal(
      [ 'chain3' ],
      comparison.new,
      'Two compared tables with one additional chain should show this.'
    )

    assert_equal(
      [ 
        'Changed table: table1',
        'New chain:',
        ':chain3 ACCEPT',
        '-A chain3 -m comment --comment "comment3"',
        '-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT',
        '-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT'
      ],
      comparison.as_array,
      'When compared as array, two compared tables with one additional chain should show this.'
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

    assert_equal(
      [ 
        'Changed table: table1',
        'Changed chain: chain1',
        '-1: -A chain1 -p tcp -m tcp --dport 1 -j ACCEPT',
        '+1: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT'
      ],
      comparison.as_array,
      'When compared as array, two compared tables with one changed chain rule should show this.'
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
    assert(
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

    assert(
      comparison.equal?,
      'Chains with same rules and policies should evaluate as equal.'
    )

    assert_equal(
      [],
      comparison.as_array,
      'When compared as array, chains with same rules and policies should return empty array.'
    )
  end

  def test_unequal_names
    test_iptables2 = IPTables::Tables.new(
      <<-EOS.dedent
        *table1
        :chain2 ACCEPT [0:0]
        -A chain2 -m comment --comment "comment1"
        -A chain2 -p tcp -m tcp --dport 1 -j ACCEPT
        -A chain2 -p tcp -m tcp --dport 2 -j ACCEPT
        COMMIT
      EOS
    )
    table2_chain = test_iptables2.tables['table1'].chains['chain2']
    assert_raise( RuntimeError, 'first and second chain should have same name' ) { 
      IPTables::ChainComparison.new(@table1_chain, table2_chain)
    }
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
    assert(
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

    assert_equal(
      [ 
        'Changed chain: chain1',
        '-0: -A chain1 -m comment --comment "comment1"',
        '+0: -A chain1 -m comment --comment "differing comment1"',
      ],
      comparison.as_array,
      'When compared as array, chains with changed rules should show this.'
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

    assert_equal(
      [ 
        'Changed chain: chain1',
        '-2: -A chain1 -p tcp -m tcp --dport 2 -j ACCEPT'
      ],
      comparison.as_array,
      'When compared as array, chains with missing rules should show this.'
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

    assert_equal(
      [ 
        'Changed chain: chain1',
        '+2: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT',
        '+3: -A chain1 -p tcp -m tcp --dport 12 -j ACCEPT' 
      ],
      comparison.as_array,
      'When compared as array, chains with additional rules should show this.'
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

    assert(
      comparison.new_policy?,
      'When compared, chains with new policy should show this.'
    )

    assert_equal(
      [ 
        'Changed chain: chain1',
        'New policy: REJECT' 
      ],
      comparison.as_array,
      'When compared as array, chains with new policy should show this.'
    )
  end
end

class TestRuleComparison < Test::Unit::TestCase
  def setup
    @iptables_text = 
      <<-EOS.dedent
        *table1
        :chain1 ACCEPT [0:0]
        -A chain1 -s 192.168.100.0/255.255.255.0 -d 192.168.100.107 -i eth1 -j ACCEPT
        COMMIT
      EOS
    @table1_chain = IPTables::Tables.new(@iptables_text).tables['table1'].chains['chain1']
  end

  def test_equal
    iptables2_text = 
      <<-EOS.dedent
        *table1
        :chain1 ACCEPT [0:0]
        -A chain1 -s 192.168.100.0/24 -d 192.168.100.107/32 -i eth1 -j ACCEPT
        COMMIT
      EOS
    test_iptables2 = IPTables::Tables.new(iptables2_text)
    table2_chain = test_iptables2.tables['table1'].chains['chain1']
    comparison = IPTables::ChainComparison.new(@table1_chain, table2_chain)
    comparison.debug

    assert(
      comparison.equal?,
      'Rules with variant forms of ip/subnet should evaluate as equal.'
    )
  end
end
