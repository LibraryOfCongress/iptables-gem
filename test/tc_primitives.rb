require 'common'

class TestPrimitives < Test::Unit::TestCase
	def test_initialize
		assert_raise( RuntimeError ) { IPTables::Primitives.new(1) }
		assert_raise( RuntimeError ) { IPTables::Primitives.new({'test_primitive', 1}) }

		assert_equal({}, IPTables::Primitives.new({}).children)
		assert_equal({'test_primitive' => []}, IPTables::Primitives.new({'test_primitive' => []}).children)

		primitives = IPTables::Primitives.new({'test_primitive' => {}})
		assert_kind_of(IPTables::Primitives, primitives.children['test_primitive'])
	end

	def test_substitute
		test_data = {
			'first' => {
				'second' => 'blah'
			}
		}
		primitives = IPTables::Primitives.new(test_data)
		assert_raise( RuntimeError ) { primitives.substitute('no') }
		assert_equal('blah', primitives.substitute('first.second'))
	end
end
