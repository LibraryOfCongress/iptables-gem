#!/usr/bin/env ruby
# Check whether the active firewall matches the merged/policy firewall

config_path = '/var/lib/iptables'
json_configs = %w/policy6 policy services macros rules primitives/
@verbosity = 0
compare_comments = true

def exit_status(status = 0)
	if @verbosity > 0
		case status
		when 0
			colored = "0 (OK)".green
		when 1
			colored = "1 (Warning)".yellow
		when 2
			colored = '2 (Critical)'.red
		when 3
			colored = '3 (Unknown)'.red
		else
			colored = "#{status} (Not a Nagios status)".yellow
		end
		puts "exiting with status ".green + colored
	end
	exit status
end

# handle command-line args
ARGV.each{ |arg|
	case arg
	when /^-c/
		raise "specify configuration path using format '-c=/the/path'" unless arg.match(/^-c=(.+)/)
		config_path = $1

	when /^\-*h/, /^help/
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

		puts "
		### #{$0} ###
		check whether firewall is applied
		firewall configurations path: #{config_path}
		configuration json files:
		  #{json_configs.join(' ')}
		options:
		  -c=/path/to/configuration:
		     path for firewall configurations
		     leave blank for default
		  -h: this help
		  -ignore-comments:
		     when comparing firewalls, ignore comment differences
		  -l=/path/to/library:
		     path to iptables library, for testing
		     leave blank for default
		  -v: run verbosely
		     add more Vs for increased verbosity
		".dedent
		exit

	when /^-ignore-comments/
		compare_comments = false

	when /^-l/
		# to test with a custom iptables lib:
		raise "specify library path using format '-l=/the/path'" unless arg.match(/^-l=(.+)/)
		raise "library path not found" unless File.directory? $1
		require 'rubygems'
		$:.unshift $1

	when /^-(v+)/
		@verbosity = $1.length

		# since we're verbose, make some colors
		class String
			def colorize(color_code)
				"\e[#{color_code}m#{self}\e[0m"
			end

			def green
				colorize(32)
			end

			def red
				colorize(31)
			end

			def yellow
				colorize(33)
			end
		end

	else
		raise "unknown argument: #{arg}"
	end
}

%w/rubygems iptables/.each{ |module_name|
	begin
		require "#{module_name}"
	rescue LoadError
		puts "UNKNOWN: unable to load module '#{module_name}'"
		exit_status 3
	end
}

if @verbosity > 2
	require 'logger'
	$log = Logger.new(STDOUT)
	$log.level = Logger::DEBUG
end

config = IPTables::Configuration.new
puts "reading configs".green if @verbosity > 0
json_configs.each{ |config_type|
	config_file_path = "#{config_path}/#{config_type}.json"
	puts " - #{config_file_path}".green if @verbosity > 1
	unless File.readable? config_file_path
		puts "UNKNOWN: could not read #{config_file_path}"
		exit_status 3
	end
	begin
		config.parse_files(config_file_path)
	rescue Exception => e
		raise e if @verbosity > 0
		puts "UNKNOWN: parsing #{config_file_path} failed: #{e.message}"
		exit_status 3
	end
}

puts "converging firewall".green if @verbosity > 0
begin
	policy_fw = config.converge_firewall
	puts '--- CONVERGED FIREWALL BEGIN ---'.yellow if @verbosity > 1
	puts policy_fw.as_array if @verbosity > 1
	puts '--- CONVERGED FIREWALL END ---'.yellow if @verbosity > 1
rescue Exception => e
	raise e if @verbosity > 0
	puts "UNKNOWN: firewall converge failed: #{e.message}"
	exit_status 3
end

puts "retrieving active firewall".green if @verbosity > 0
iptables_save = %x/iptables-save/
puts '--- RETRIEVED FIREWALL BEGIN ---'.yellow if @verbosity > 1
puts iptables_save if @verbosity > 1
puts '--- RETRIEVED FIREWALL END ---'.yellow if @verbosity > 1
if iptables_save.empty?
	puts "UNKNOWN: iptables-save output is empty; do you have root permissions?"
	exit_status 3
end

puts "parsing active firewall".green if @verbosity > 0
begin
	active_firewall = IPTables::Tables.new(iptables_save)
	puts '--- PARSED FIREWALL BEGIN ---'.yellow if @verbosity > 1
	puts active_firewall.as_array if @verbosity > 1
	puts '--- PARSED FIREWALL END ---'.yellow if @verbosity > 1
rescue Exception => e
	raise e if @verbosity > 0
	puts "UNKNOWN: unable to parse active firewall: #{e.message}"
	exit_status 3
end

puts "comparing active firewall to converged firewall".green if @verbosity > 0
puts "differences in comments are ".green + (compare_comments ? 'compared'.green : 'ignored'.red) if @verbosity > 0
comparison = IPTables::TablesComparison.new(active_firewall, policy_fw)
comparison.ignore_comments unless compare_comments
unless comparison.equal?
	if @verbosity > 2
		require 'pp'
		puts "--- BEGIN ACTIVE_FIREWALL AS ARRAY ---".yellow
		pp active_firewall.as_array(comments = compare_comments)
		puts "--- END ACTIVE_FIREWALL AS ARRAY ---".yellow
		puts "--- BEGIN POLICY_FIREWALL AS ARRAY ---".yellow
		pp policy_fw.as_array(comments = compare_comments)
		puts "--- END POLICY_FIREWALL AS ARRAY ---".yellow
	end
	puts "--- BEGIN NAGIOS MESSAGE ---".yellow if @verbosity > 0
	puts "WARNING: firewall needs to be applied"
	puts comparison.as_array.join("\n")
	puts "--- END NAGIOS MESSAGE ---".yellow if @verbosity > 0
	exit_status 1
end

puts "Nagios message:" if @verbosity > 0
puts "OK: active firewall matches policy firewall"
exit_status
