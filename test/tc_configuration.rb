require 'common'

class TestConfiguration < Test::Unit::TestCase
  def setup
    @test_config = IPTables::Configuration.new()
  end

  def test_initialize
    assert_nothing_raised( RuntimeError ) { IPTables::Configuration.new() }
  end

  def test_parse_files
    assert_raise( RuntimeError ) { IPTables::Configuration.new('foobar') }
    # don't know how to test reading .json files
    # without being able to test reading json, can not complete testing
    #assert_nothing_raised( RuntimeError ) { IPTables::Configuration.new('test/test_config.json') }
  end

  def test_policy
    assert_raise( RuntimeError ) { @test_config.policy }
    assert_equal({}, @test_config.policy({}))
  end

  def test_policy6
    assert_raise( RuntimeError ) { @test_config.policy6 }
    assert_equal({}, @test_config.policy6({}))
  end

  def test_interpolations
    assert_raise( RuntimeError ) { @test_config.interpolations }
  end

  def test_primitives
    assert_raise( RuntimeError ) { @test_config.primitives }
  end

  def test_rules
    assert_raise( RuntimeError ) { @test_config.rules }
    assert_equal({}, @test_config.rules({}))
  end

  def test_services
    assert_raise( RuntimeError ) { @test_config.services }
  end

  def test_macros
    assert_raise( RuntimeError ) { @test_config.macros }
  end

  def test_converge_firewall
    assert_raise( RuntimeError ) { @test_config.converge_firewall() }

    test_policy = IPTables::Tables.new({
      'table1' => {
        'chain1' => {
          'policy' => 'ACCEPT',
          'rules' => [
            '-j ACCEPT'
          ]
        }
      }
    }, @test_config)
    @test_config.policy(test_policy)

    test_rules = IPTables::Tables.new({
      'table1' => { 'chain1' => { 'policy' => 'DROP' } }
    }, @test_config)
    @test_config.rules(test_policy)

    assert_instance_of(IPTables::Tables, @test_config.converge_firewall)
  end
end
