# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "date"


# Send events to a syslog server.
#
# You can send messages compliant with RFC3164 or RFC5424
# using either UDP or TCP as the transport protocol.
#
# By default the contents of the `message` field will be shipped as
# the free-form message text part of the emitted syslog message. If
# your messages don't have a `message` field or if you for some other
# reason want to change the emitted message, modify the `message`
# configuration option.
class LogStash::Outputs::Syslog < LogStash::Outputs::Base
  config_name "syslog"

  FACILITY_LABELS = [
    "kernel",
    "user-level",
    "mail",
    "daemon",
    "security/authorization",
    "syslogd",
    "line printer",
    "network news",
    "uucp",
    "clock",
    "security/authorization",
    "ftp",
    "ntp",
    "log audit",
    "log alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
  ]

  SEVERITY_LABELS = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
  ]

  # syslog server address to connect to
  config :host, :validate => :string, :required => true
  
  # syslog server port to connect to
  config :port, :validate => :number, :required => true

  # syslog server protocol. you can choose between udp, tcp and ssl/tls over tcp
  config :protocol, :validate => ["tcp", "udp", "ssl-tcp"], :default => "udp"

  # Verify the identity of the other end of the SSL connection against the CA.
  config :ssl_verify, :validate => :boolean, :default => false

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path

  # SSL certificate path
  config :ssl_cert, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  # facility label for syslog message
  config :facility, :validate => FACILITY_LABELS, :required => true

  # severity label for syslog message
  config :severity, :validate => SEVERITY_LABELS, :required => true

  # source host for syslog message
  config :sourcehost, :validate => :string, :default => "%{host}"

  # timestamp for syslog message
  config :timestamp, :validate => :string, :default => "%{@timestamp}", :deprecated => "This setting is no longer necessary. The RFC setting will determine what time format is used."

  # application name for syslog message
  config :appname, :validate => :string, :default => "LOGSTASH"

  # process id for syslog message
  config :procid, :validate => :string, :default => "-"

  # message text to log
  config :message, :validate => :string, :default => "%{message}"
 
  # message id for syslog message
  config :msgid, :validate => :string, :default => "-"

  # syslog message format: you can choose between rfc3164 or rfc5424
  config :rfc, :validate => ["rfc3164", "rfc5424"], :default => "rfc3164"

  private
  def setup_ssl
    require "openssl"
    @ssl_context = OpenSSL::SSL::SSLContext.new
    @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
    @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key),@ssl_key_passphrase)
    if @ssl_verify
      @cert_store = OpenSSL::X509::Store.new
      # Load the system default certificate path to the store
      @cert_store.set_default_paths
      if File.directory?(@ssl_cacert)
        @cert_store.add_path(@ssl_cacert)
      else
        @cert_store.add_file(@ssl_cacert)
      end
      @ssl_context.cert_store = @cert_store
      @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    end
  end 

  public
  def register
    @client_socket = nil
    if ssl?
      setup_ssl
    end 
  end

  private
  def udp?
    @protocol == "udp"
  end

  private
  def ssl?
    @protocol == "ssl-tcp"
  end

  private
  def rfc3164?
    @rfc == "rfc3164"
  end 

  private
  def connect
    if udp?
        @client_socket = UDPSocket.new
        @client_socket.connect(@host, @port)
    else
        @client_socket = TCPSocket.new(@host, @port)
        if ssl?
          @client_socket = OpenSSL::SSL::SSLSocket.new(@client_socket, @ssl_context)
          begin
            @client_socket.connect
          rescue OpenSSL::SSL::SSLError => ssle
            @logger.error("SSL Error", :exception => ssle,
                          :backtrace => ssle.backtrace)
            # NOTE(mrichar1): Hack to prevent hammering peer
            sleep(5)
            raise
          end
        end
    end
  end

  public
  def receive(event)
    

    appname = event.sprintf(@appname)
    procid = event.sprintf(@procid)
    sourcehost = event.sprintf(@sourcehost)

    facility_code = FACILITY_LABELS.index(@facility)

    severity_code = SEVERITY_LABELS.index(@severity)

    priority = (facility_code * 8) + severity_code

    if rfc3164?
      timestamp = event.sprintf("%{+MMM dd HH:mm:ss}")
      syslog_msg = "<"+priority.to_s()+">"+timestamp+" "+sourcehost+" "+appname+"["+procid+"]: "+event.sprintf(@message)
    else
      msgid = event.sprintf(@msgid)
      timestamp = event.sprintf("%{+YYYY-MM-dd'T'HH:mm:ss.SSSZZ}")
      syslog_msg = "<"+priority.to_s()+">1 "+timestamp+" "+sourcehost+" "+appname+" "+procid+" "+msgid+" - "+event.sprintf(@message)
    end

    begin
      connect unless @client_socket
      @client_socket.write(syslog_msg + "\n")
    rescue => e
      @logger.warn(@protocol+" output exception", :host => @host, :port => @port,
                 :exception => e, :backtrace => e.backtrace)
      @client_socket.close rescue nil
      @client_socket = nil
    end
  end
end

