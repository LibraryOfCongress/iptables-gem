require 'common'

class TestMacros < Test::Unit::TestCase
	def test_initialize
		assert_equal({}, IPTables::Macros.new({}).named)
		assert_instance_of(IPTables::Macro, IPTables::Macros.new({'test_macro' => {}}).named['test_macro'])
	end
end

class TestMacro < Test::Unit::TestCase
	def test_initialize
		assert_raise( RuntimeError ) { IPTables::Macro.new('test_macro', 1) }

		assert_equal('test_macro', IPTables::Macro.new('test_macro', {}).name)
		assert_equal([], IPTables::Macro.new('test_macro', []).children)
		assert_equal([{}], IPTables::Macro.new('test_macro', {}).children)
		assert_equal([{'raw' => ''}], IPTables::Macro.new('test_macro', '').children)
		assert_equal([{'raw' => ''}], IPTables::Macro.new('test_macro', [{'raw' => ''}]).children)
	end
end

class TestServices < Test::Unit::TestCase
	def test_initialize
		assert_equal({}, IPTables::Services.new({}).named)
		assert_instance_of(IPTables::Service, IPTables::Services.new({'test_service' => 1}).named['test_service'])
	end
end

class TestService < Test::Unit::TestCase
	def test_initialize
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', 1.0) }
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', []) }
		assert_raise( RuntimeError ) { IPTables::Service.new('test_service', {}) }

		assert_equal('test_service', IPTables::Service.new('test_service', 1).name)
	end

	def test_handle_string
		assert_equal([{"comment"=>"_ test_service"}, {"raw"=>"-j ACCEPT"}], IPTables::Service.new('test_service', '-j ACCEPT').children)
	end

	def test_handle_array
		assert_equal([{"comment"=>"_ test_service"}, {"raw"=>"-j ACCEPT"}], IPTables::Service.new('test_service', [{'raw' => '-j ACCEPT'}]).children)
	end

	def test_handle_hash
		assert_equal([{"raw"=>"-j ACCEPT", "service_name"=>"test_service"}], IPTables::Service.new('test_service', {'raw' => '-j ACCEPT'}).children)
	end

	def test_handle_integer
		assert_equal(
			[
				{"comment"=>"_ Port 1 - test_service"},
				{"raw"=> "-p tcp -m tcp --sport 1024:65535 --dport 1 -m state --state NEW,ESTABLISHED -j ACCEPT"}
			], 
		IPTables::Service.new('test_service', 1).children
	)
	end
end

class TestInterpolations < Test::Unit::TestCase
	def test_initialize
		new = IPTables::Interpolations.new({})
		assert_equal({}, new.named)
	end

	def test_add
		new = IPTables::Interpolations.new({})
		new.add('test_interpolation')
		assert_instance_of(IPTables::Interpolation, new.named['test_interpolation'])
	end

	def test_children
		new = IPTables::Interpolations.new({})
		new.add('test_interpolation')
		assert_equal([{"raw"=>"test_interpolation"}], new.children('test_interpolation'))
		assert_equal([{"raw"=>"test_interpolation"}], new.children(['test_interpolation']))
	end
end
