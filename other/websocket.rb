
# Python WebSocket library with support for "wss://" encryption.
# Copyright 2011 Joel Martin
# Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
# 
# Supports following protocol versions:
#     - http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-75
#     - http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76
#     - http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-10

require 'gserver'
require 'stringio'
require 'digest/md5'
require 'base64'

class EClose < Exception
end

class WebSocketServer < GServer
  @@buffer_size = 65536

  @@server_handshake_hixie = "HTTP/1.1 101 Web Socket Protocol Handshake\r
Upgrade: WebSocket\r
Connection: Upgrade\r
%sWebSocket-Origin: %s\r
%sWebSocket-Location: %s://%s%s\r
"

  def initialize(port, host, opts, *args)
    vmsg "in WebSocketServer.initialize"

    super(port, host, *args)
   
    @verbose = opts['verbose']
    @opts = opts
    # Keep an overall record of the client IDs allocated
    # and the lines of chat
    @@client_id = 0
  end
  
  #
  # WebSocketServer logging/output functions
  #
  def traffic(token)
    if @verbose
      print token
      STDOUT.flush
    end
  end

  def msg(msg)
    puts "% 3d: %s" % [@my_client_id, msg]
  end

  def vmsg(msg)
    if @verbose
      msg(msg)
    end
  end

  def gen_md5(h)
    key1 = h['sec-websocket-key1']
    key2 = h['sec-websocket-key2']
    key3 = h['key3']
    spaces1 = key1.count(" ")
    spaces2 = key2.count(" ")
    num1 = key1.scan(/[0-9]/).join('').to_i / spaces1
    num2 = key2.scan(/[0-9]/).join('').to_i / spaces2

    return Digest::MD5.digest([num1, num2, key3].pack('NNa8'))
  end

  def encode_hixie(buf)
    return ["\x00" + Base64.encode64(buf).gsub(/\n/, '') + "\xff", 1, 1]
  end

  def decode_hixie(buf)
    last = buf.index("\377")
    return {'payload' => Base64.decode64(buf[1...last]),
            'hlen' => 1,
            'length' => last - 1,
            'left' => buf.length - (last + 1)}
  end

  def send_frames(bufs)
    if bufs.length > 0
      encbuf = ""
      bufs.each do |buf|
        #puts "Sending frame: #{buf.inspect}"
        encbuf, lenhead, lentail = encode_hixie(buf)
      
        @send_parts << encbuf
      end

    end

    while @send_parts.length > 0
      buf = @send_parts.shift
      sent = @client.send(buf, 0)

      if sent == buf.length
        traffic "<"
      else
        traffic "<."
        @send_parts.unshift(buf[sent...buf.length])
      end
    end

    return @send_parts.length
  end

  # Receive and decode Websocket frames
  # Returns: [bufs_list, closed_string]
  def recv_frames()
    closed = false
    bufs = []

    buf = @client.recv(@@buffer_size)

    if buf.length == 0
      return bufs, "Client closed abrubtly"
    end

    if @recv_part
      buf = @recv_part + buf
      @recv_part = nil
    end

    while buf.length > 0
      if buf[0...2] == "\xff\x00":
        closed = "Client sent orderly close frame"
        break
      elsif buf[0...2] == "\x00\xff":
        # Partial frame
        traffic "}."
        @recv_part = buf
        break
      end

      frame = decode_hixie(buf)
      #msg "Receive frame: #{frame.inspect}"

      traffic "}"

      bufs << frame['payload']

      if frame['left'] > 0:
        buf = buf[buf.length-frame['left']...buf.length]
      else
        buf = ''
      end
    end

    return bufs, closed
  end


  def send_close(code=nil, reason='')
    buf = "\xff\x00"
    @client.send(buf, 0)
  end

  def do_handshake(sock)

    if !IO.select([sock], nil, nil, 3)
      raise EClose, "ignoring socket not ready"
    end

    handshake = sock.recv(1024, Socket::MSG_PEEK)
    #puts "Handshake [#{handshake.inspect}]"

    if handshake == ""
      raise(EClose, "ignoring empty handshake")
    else
      scheme = "ws"
      retsock = sock
      sock.recv(1024)
    end

    h = @headers = {}
    hlines = handshake.split("\r\n")
    req_split = hlines.shift.match(/^(\w+) (\/[^\s]*) HTTP\/1\.1$/) 
    @path = req_split[2].strip
    hlines.each do |hline|
      break if hline == ""
      hsplit = hline.match(/^([^:]+):\s*(.+)$/)
      h[hsplit[1].strip.downcase] = hsplit[2]
    end
    #puts "Headers: #{h.inspect}"

    if h.has_key?('upgrade') &&
       h['upgrade'].downcase == 'websocket'
      msg "Got WebSocket connection"
    else
      raise EClose, "Non-WebSocket connection"
    end

    body = handshake.match(/\r\n\r\n(........)/)
    if body
      h['key3'] = body[1]
      trailer = gen_md5(h)
      pre = "Sec-"
      protocols = h["sec-websocket-protocol"]
    else
      raise EClose, "Only Hixie-76 supported for now"
    end

    response = sprintf(@@server_handshake_hixie, pre, h['origin'],
      pre, "ws", h['host'], @path)

    if protocols.include?('base64')
      response += sprintf("%sWebSocket-Protocol: base64\r\n", pre)
    else
      msg "Warning: client does not report 'base64' protocol support"
    end

    response += "\r\n" + trailer

    #puts "Response: [#{response.inspect}]"

    retsock.send(response, 0)

    return retsock
  end

  def serve(io)
    @@client_id += 1
    @my_client_id = @@client_id

    @send_parts = []
    @recv_part = nil
    @base64 = nil

    begin
      @client = do_handshake(io)
      new_client
    rescue EClose => e
      msg "Client closed: #{e.message}"
      return
    rescue Exception => e
      msg "Uncaught exception: #{e.message}"
      msg "Trace: #{e.backtrace}"
      return
    end

    msg "Client disconnected"
  end
end

# vim: sw=2
