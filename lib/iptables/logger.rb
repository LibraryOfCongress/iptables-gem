require 'logger'
unless($log)
  $log = Logger.new(STDOUT)
  $log.level = Logger::WARN
end
