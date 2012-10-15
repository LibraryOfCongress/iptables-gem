require 'rcov/rcovtask'

task :default => [:rcov]

desc "RCov"
Rcov::RcovTask.new do | t |
	t.libs << 'test'
	t.test_files = FileList[ 'test/tc_all.rb' ]
	t.rcov_opts << '--exclude /var'
end
