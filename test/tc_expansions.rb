require 'common'

class TestMacros < Test::Unit::TestCase
	def test_empty
		assert_equal({}, IPTables::Macros.new({}).named)
	end
end

class TestMacro < Test::Unit::TestCase
	def test_macro
		assert_raise( RuntimeError ) { IPTables::Macro.new('test_macro', 1) }

		assert_equal('test_macro', IPTables::Macro.new('test_macro', {}).name)
		assert_equal([], IPTables::Macro.new('test_macro', []).children)
		assert_equal([{}], IPTables::Macro.new('test_macro', {}).children)
		assert_equal([{'raw' => ''}], IPTables::Macro.new('test_macro', '').children)
		assert_equal([{'raw' => ''}], IPTables::Macro.new('test_macro', [{'raw' => ''}]).children)
	end
end

class TestServices < Test::Unit::TestCase
	def test_services
		assert_equal({}, IPTables::Services.new({}).named)
	end
end

class TestService < Test::Unit::TestCase
	def test_service
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', 1.0) }
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', []) }
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', {}) }

		assert_equal('test_service', IPTables::Service.new('test_service', 1).name)
		#assert_equal([], IPTables::Service.new('test_service', [{}]).children)
		#assert_equal([{}], IPTables::Service.new('test_service', {}).children)
		#assert_equal([{'raw' => ''}], IPTables::Service.new('test_service', '').children)
		#assert_equal([{'raw' => ''}], IPTables::Service.new('test_service', [{'raw' => ''}]).children)
	end
end
