# this setup code is required by all tests
require 'rubygems'
$:.unshift(File.dirname(__FILE__) + '/../lib') unless $:.include?('/../lib')
require 'iptables'
require 'test/unit'

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
