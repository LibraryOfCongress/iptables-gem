# this setup code is required by all tests
require 'rubygems'
$:.unshift(File.dirname(__FILE__) + '/../lib') unless $:.include?('/../lib')
require 'iptables'
require 'test/unit'
