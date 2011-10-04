#!/usr/bin/env ruby

# A WebSocket to TCP socket proxy with support for "wss://" encryption.
# Copyright 2011 Joel Martin
# Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)

require 'socket'
$: << "other"
$: << "../other"
require 'websocket'
require 'optparse'

class WebSocketProxy < WebSocketServer

  def initialize(port, host, opts, *args)
    vmsg "in WebSocketProxy.initialize"

    super(port, host, opts, *args)
    
    @target_host = opts["target_host"]
    @target_port = opts["target_port"]
  end

  # Echo back whatever is received    
  def new_client()
    vmsg "in new_client"

    tsock = TCPSocket.open(@target_host, @target_port)
    msg "opened target socket"

    begin
      do_proxy(tsock)
    rescue
      tsock.shutdown(Socket::SHUT_RDWR)
      tsock.close
      raise
    end
  end


  def do_proxy(target)

    cqueue = []
    c_pend = 0
    tqueue = []
    rlist = [@client, target]

    loop do
      wlist = []

      if tqueue.length > 0
        wlist << target
      end
      if cqueue.length > 0 || c_pend > 0
        wlist << @client
      end

      ins, outs, excepts = IO.select(rlist, wlist, nil, 0.001)
      if excepts && excepts.length > 0
        raise Exception, "Socket exception"
      end

      if outs && outs.include?(target)
        # Send queued client data to the target
        dat = tqueue.shift
        sent = target.send(dat, 0)
        if sent == dat.length
          traffic ">"
        else
          tqueue.unshift(dat[sent...dat.length])
          traffic ".>"
        end
      end

      if ins && ins.include?(target)
        # Receive target data and queue for the client
        buf = target.recv(@@buffer_size)
        if buf.length == 0:
          raise EClose, "Target closed"
        end

        cqueue << buf
        traffic "{"
      end

      if outs && outs.include?(@client)
        # Encode and send queued data to the client
        c_pend = send_frames(cqueue)
        cqueue = []
      end

      if ins && ins.include?(@client)
        # Receive client data, decode it, and send it back
        frames, closed = recv_frames
        tqueue += frames
        #msg "[#{cqueue.inspect}]"

        if closed
          send_close
          raise EClose, closed
        end
      end

    end  # loop
  end
end

# Parse parameters
opts = {}
parser = OptionParser.new do |o|
  o.on('--verbose', '-v') { |b| opts['verbose'] = b }
  o.parse!
end
puts "opts: #{opts.inspect}"
puts "ARGV: #{ARGV.inspect}"

if ARGV.length < 2:
  puts "Too few arguments"
  exit 2
end

# Parse host:port and convert ports to numbers
if ARGV[0].count(":") > 0
  opts['listen_host'], _, opts['listen_port'] = ARGV[0].rpartition(':')
else
  opts['listen_host'], opts['listen_port'] = GServer::DEFAULT_HOST, ARGV[0]
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

puts "Starting server on #{opts['listen_host']}:#{opts['listen_port']}"
server = WebSocketProxy.new(opts['listen_port'], opts['listen_host'], opts)
#server = WebSocketProxy.new(opts['listen_port'])
server.start

loop do
  break if server.stopped?
end

puts "Server has been terminated"

# vim: sw=2
