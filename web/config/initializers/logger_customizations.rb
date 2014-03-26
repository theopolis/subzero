# config/initializers/logger_customizations.rb
# Production-only monkeypatches to make our logs awesome
  
# Monkeypatch round 2
# * add timestamps + loglevel
# * skip "Rendered partial..." lines
class ActiveSupport::Logger::SimpleFormatter
  def call(severity, time, progname = nil, msg)
    # Skip "Rendered..." messages in production
    if msg =~ /Rendered/
      return
    end

    "%s\n" % msg
  end
end