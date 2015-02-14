#!/usr/bin/env ruby

# A WebSocket to TCP socket proxy
# Copyright 2011 Joel Martin
# Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)

require 'socket'
$: << "other"
$: << "../other"
require 'websocket'
require 'optparse'
require 'fileutils'

# Proxy traffic to and from a WebSockets client to a normal TCP
# socket server target. All traffic to/from the client is base64
# encoded/decoded to allow binary data to be sent/received to/from
# the target.
class WebSocketProxy < WebSocketServer
  attr_accessor 'target_host', 'target_port'
  attr_reader :opts, :quit

  @@Traffic_legend = "
Traffic Legend:
    }  - Client receive
    }. - Client receive partial
    {  - Target receive

    >  - Target send
    >. - Target send partial
    <  - Client send
    <. - Client send partial
"


  def initialize(opts)
    vmsg "in WebSocketProxy.initialize"
    @opts = opts
    
    super(opts)

    @target_host = opts['target_host']
    @target_port = opts['target_port']
    
    #replace the logfile option with the expanded path
    opts[:logfile] = File.expand_path(logfile) if logfile?
    opts[:pidfile] = File.expand_path(pidfile) if pidfile?
  end
  
  def daemonize?
    opts[:daemonize]
  end

  def logfile
    opts[:logfile]
  end

  def pidfile
    opts[:pidfile]
  end

  def logfile?
    !logfile.nil?
  end

  def pidfile?
    !pidfile.nil?
  end
  
  def write_pid
    if pidfile?
      begin
        File.open(pidfile, ::File::CREAT | ::File::EXCL | ::File::WRONLY){|f| f.write("#{Process.pid}") }
        at_exit { File.delete(pidfile) if File.exists?(pidfile) }
      rescue Errno::EEXIST
        check_pid
        retry
      end
    end
  end
  
  def check_pid
    if pidfile?
      case pid_status(pidfile)
      when :running, :not_owned
        log "A server is already running. Check #{pidfile}"
        exit(1)
      when :dead
        File.delete(pidfile)
      end
    end
  end

  def pid_status(pidfile)
    return :exited unless File.exists?(pidfile)
    pid = ::File.read(pidfile).to_i
    return :dead if pid == 0
    Process.kill(0, pid)      # check process status
    :running
  rescue Errno::ESRCH
    :dead
  rescue Errno::EPERM
    :not_owned
  end
  
  def redirect_output
    FileUtils.mkdir_p(File.dirname(logfile), :mode => 0755)
    FileUtils.touch logfile
    File.chmod(0644, logfile)
    $stderr.reopen(logfile, 'a')
    $stdout.reopen($stderr)
    $stdout.sync = $stderr.sync = true
  end
  
  def suppress_output
    $stderr.reopen('/dev/null', 'a')
    $stdout.reopen($stderr)
  end
  
  def trap_signals
    trap(:QUIT) do   # kill -9
      log "Hard killing websockify server..."
      stop
      log "Bye!"
    end
    
    trap(:TERM) do   # kill -15
      log "Gracefully shutting down websockify server..."
      Thread.new { shutdown; exit }
      log "Bye!"
    end
  end
  
  def daemonize
    exit if fork
    Process.setsid
    exit if fork
    Dir.chdir "/"
  end
  
  def run!(max_connections)
    check_pid
    daemonize if daemonize?
    write_pid
    trap_signals
    
    if logfile?
      redirect_output
    elsif daemonize?
      suppress_output
    end
    
    log "Starting Websockify server on #{opts['listen_host']}:#{opts['listen_port']} and proxying to #{target_host}:#{target_port}"
    
    #tell gserver to start
    start(max_connections)
    
    #join the gserver thread to this one
    join
  end

  # Echo back whatever is received
  def new_websocket_client(client)
    path = Thread.current[:path]
    msg "path = #{path}"
    if path =~ /:/
      msg "path has a ip and port"
      possible_target_host = path[/(\d+\.\d+\.\d+\.\d+):(\d+)/,1]
      possible_target_port = path[/(\d+\.\d+\.\d+\.\d+):(\d+)/,2].to_i
    end
    Thread.current[:path] = "/"

    if possible_target_host and possible_target_port
      @target_host = possible_target_host
      @target_port = possible_target_port
    end

    msg "connecting to: %s:%s" % [@target_host, @target_port]
    tsock = TCPSocket.open(@target_host, @target_port)

    if @verbose then log @@Traffic_legend end

    begin
      do_proxy(client, tsock)
    rescue
      tsock.shutdown(Socket::SHUT_RDWR)
      tsock.close
      raise
    end
  end

  # Proxy client WebSocket to normal target socket.
  def do_proxy(client, target)
    cqueue = []
    c_pend = 0
    tqueue = []
    rlist = [client, target]

    loop do
      wlist = []

      if tqueue.length > 0
        wlist << target
      end
      if cqueue.length > 0 || c_pend > 0
        wlist << client
      end

      ins, outs, excepts = IO.select(rlist, wlist, nil, 0.001)
      if excepts && excepts.length > 0
        raise Exception, "Socket exception"
      end

      # Send queued client data to the target
      if outs && outs.include?(target)
        dat = tqueue.shift
        sent = target.send(dat, 0)
        if sent == dat.length
          traffic ">"
        else
          tqueue.unshift(dat[sent...dat.length])
          traffic ".>"
        end
      end

      # Receive target data and queue for the client
      if ins && ins.include?(target)
        buf = target.recv(@@Buffer_size)
        if buf.length == 0
          raise EClose, "Target closed"
        end

        cqueue << buf
        traffic "{"
      end

      # Encode and send queued data to the client
      if outs && outs.include?(client)
        c_pend = send_frames(cqueue)
        cqueue = []
      end

      # Receive client data, decode it, and send it back
      if ins && ins.include?(client)
        frames, closed = recv_frames
        tqueue += frames

        if closed
          send_close
          raise EClose, closed
        end
      end

    end  # loop
  end
end

# Parse parameters

opts           = {}
version        = "1.0.0"
maxcon_help = "maximum number of connections allowed"
daemonize_help = "run daemonized in the background (default: false)"
pidfile_help   = "the pid filename"
logfile_help   = "the log filename"
include_help   = "an additional $LOAD_PATH"
debug_help     = "set $DEBUG to true"
warn_help      = "enable warnings"
usage          = "Usage: server list_port target_host'target_port' [options]"

op = OptionParser.new
op.banner =  "Websockify Server #{version}"
op.separator ""
op.separator "#{usage}"
op.separator ""

op.separator "Process options:"
op.on("-m", "--maxcon NUMBER", maxcon_help)    { |value| opts[:maxcon]    = value || 100 }
op.on("-d", "--daemonize",     daemonize_help) {         opts[:daemonize] = true  }
op.on("-p", "--pid PIDFILE",   pidfile_help)   { |value| opts[:pidfile]   = value }
op.on("-l", "--log LOGFILE",   logfile_help)   { |value| opts[:logfile]   = value }
op.separator ""

op.separator "Ruby options:"
op.on("-I", "--include PATH", include_help) { |value| $LOAD_PATH.unshift(*value.split(":").map{|v| File.expand_path(v)}) }
op.on(      "--debug",        debug_help)   { $DEBUG = true }
op.on(      "--warn",         warn_help)    { $-w = true    }
op.separator ""

op.separator "Common options:"
op.on("-h", "--help")    { puts op.to_s; exit }
op.on("-V", "--version") { puts version; exit }
op.on("-v", "--verbose")   { |value| opts['verbose'] = true }
op.separator ""

op.parse!(ARGV)

if ARGV.length < 2
  puts "Too few arguments."
  puts op.to_s
  exit 2
end

# Parse host:port and convert ports to numbers
if ARGV[0].count(":") > 0
  opts['listen_host'], _, opts['listen_port'] = ARGV[0].rpartition(':')
else
  opts['listen_host'], opts['listen_port'] = '0.0.0.0', ARGV[0]
end

begin
  opts['listen_port'] = opts['listen_port'].to_i
rescue
  puts "Error parsing listen port"
  exit 2
end

if ARGV[1].count(":") > 0
  opts['target_host'], _, opts['target_port'] = ARGV[1].rpartition(':')
else
  puts "Error parsing target"
  exit 2
end

begin
  opts['target_port'] = opts['target_port'].to_i
rescue
  puts "Error parsing target port"
  exit 2
end

server = WebSocketProxy.new(opts)
server.run!(opts[:maxcon].to_i)

# vim: sw=2
