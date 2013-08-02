Description
===========

Iptables-gem is a Ruby API for parsing, generating, and comparing Linux
iptables rules. It is configured using JSON and oriented toward use
within configuration-management software such as
[http://www.opscode.com/chef/](Chef).

Requirements
============

## Ruby:

* Ruby: 1.8
* Likely also works on 1.9, but testing is giving me fits so I am ignoring it for now

## Platforms:

The following platforms and versions are tested:

* Ubuntu 10.04, 12.04
* CentOS 6.4, Red Hat 6.4

Ruby Usage
==========

Install this gem and `require iptables`. In the examples below,
`/path/to/json/` refers to the directory containing JSON policy files.
See [Generate.md](the firewall generation documentation) for information
on setting these up. There are also example configuration files in
`examples/policy/*.json`.

## Generate a firewall

You will first need to create JSON firewall configuration files. See the
`Generating a Firewall` section below for details. Once this is done,
you can generate a firewall like so:

     config = IPTables::Configuration.new
     config.parse_files('/path/to/json/')
     policy_fw = config.converge_firewall
     puts policy_fw.as_array

## Compare two firewalls

You can determine whether a proposed/policy firewall and the
currently-applied firewall are identical:

     config = IPTables::Configuration.new
     config.parse_files('/path/to/json/')
     policy_fw = config.converge_firewall
     active_fw = IPTables::Tables.new(%x/iptables-save/)
     comparison = IPTables::TablesComparison.new(active_fw, policy_fw)
     comparison.equal?

Alternately, you can compare firewalls using only `iptables-save` output:

     active_fw = IPTables::Tables.new(%x/iptables-save/)
     other_fw = IPTables::Tables.new(File.readlines('/path/to/another/saved/firewall'))
     comparison = IPTables::TablesComparison.new(active_fw, policy_fw)
     comparison.equal?

If two firewalls are the same **except** for embedded firewall comments,
you can ignore comments:

     comparison.ignore_comments
     comparison.equal?

If you want to see **exactly** how two firewalls differ:

     comparison.as_array

## Log

If you want to see debug messages, turn on logging:

     require 'logger'
     $log = Logger.new(STDOUT)
     $log.level = Logger::DEBUG
     config = IPTables::Configuration.new
     config.parse_files('/path/to/json/')
     policy_fw = config.converge_firewall

Generating a Firewall
=====================

An explanation of generating a firewall can be found within
[Generate.md](the firewall generation documentation). An example set of
configuration files to create a basic working firewall can be found in
`examples/policy/*.json`.

Included Scripts
================

## Nagios

The `bin` directory contains a Nagios helper script written in Ruby to
compare the running firewall against a "policy" firewall. To try it from
within the gem source directory (that is, without first installing the
gem), first copy `examples/policy` to a temporary location and edit the
policy files to taste. Then change to the `bin` directory and run:

`./check_firewall.rb -l=/path/to/iptables/gem/lib/ -v -c=/path/to/policy/`

The above example includes debugging information which makes it
unsuitable for use with Nagios. For "live" use with Nagios, you would
want to install this gem and run:

`check_firewall.rb -c=/path/to/policy/`

Tests
=====

To run unit tests:

* change to iptables directory
* run `rake`
* examine coverage reports in directory `coverage`

Future
======

Changes/Features I would like to see:

* Is ipv6 even working?
* Write policy in YAML **or** JSON
* Deprecate `requires_primitive`: these should be ignored if there is no matching interpolation
* Deprecate `interpolated`: these should be properly handled inside **any** kind of rule
* Deprecate `comment` and `ulog`? These seem like they ought to be macros.
* `ulog` has `-p tcp` but this seems awkward; is it even useful?
* Do other stuff like ebtables too? Not sure it's in scope here. Certainly the gem name would need to be reconsidered.
* Generate better error messages when we encounter failures parsing configurations.
* Move development/testing/coverage environment to Ruby 1.9

License and Authors
===================

* Author:: Kurt Yoder <kyoder@loc.gov>

See LICENSE file for project license information.
