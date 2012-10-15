#!/usr/bin/env ruby
#
# ./converge_config.rb - Given configuration files, show generated output rules

# gratuitously stolen from ohai
begin
	require 'rubygems'
rescue LoadError
	# must be debian! ;)
	missing_rubygems = true
end
begin
	# if we're in a source code checkout, we want to run the code from that.
	# have to do this *after* rubygems is loaded.
	$:.unshift File.expand_path('../../lib', __FILE__)
	require 'iptables'
rescue LoadError
	if missing_rubygems
		STDERR.puts "rubygems previously failed to load - is it installed?"
	end 

	raise
end

require 'pp'

config = IPTables::Configuration.new
ARGV.each{ |arg|
	config.parse_files(arg)
}
policy_fw = config.converge_firewall
pp policy_fw.as_array
