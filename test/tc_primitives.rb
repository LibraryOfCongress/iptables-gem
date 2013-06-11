require 'common'

class TestPrimitives < Test::Unit::TestCase
  def setup
    test_data = {
      'first' => {
        'second' => 'blah'
      }
    }
    @primitives = IPTables::Primitives.new(test_data)
  end

  def test_initialize
    assert_raise( RuntimeError ) { IPTables::Primitives.new(1) }
    assert_raise( RuntimeError ) { IPTables::Primitives.new({'test_primitive', 1}) }

    assert_equal({}, IPTables::Primitives.new({}).children)
    assert_equal({'test_primitive' => []}, IPTables::Primitives.new({'test_primitive' => []}).children)

    primitives = IPTables::Primitives.new({'test_primitive' => {}})
    assert_kind_of(IPTables::Primitives, primitives.children['test_primitive'])
  end

  def test_substitute
    assert_raise( RuntimeError, 'a missing substitution is an error' ) { @primitives.substitute('missing') }
    assert_raise( RuntimeError, 'a partial substitution is an error' ) { @primitives.substitute('first') }
    assert_equal('blah', @primitives.substitute('first.second'))
  end

  def test_has_primitive
    assert(@primitives.has_primitive?('first.second'), 'An existing primitive should say it exists')
    assert_equal(false, @primitives.has_primitive?('missing'), 'A missing primitive should say it does not exist')
    assert_equal(false, @primitives.has_primitive?('first'), 'A partial primitive should say it does not exist')
  end
end
