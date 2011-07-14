## websockify: WebSockets support for any application/server

websockify was formerly named wsproxy and was part of the
[noVNC](https://github.com/kanaka/noVNC) project.

At the most basic level, websockify just translates WebSockets traffic
to normal socket traffic. websockify accepts the WebSockets handshake,
parses it, and then begins forwarding traffic between the client and
the target in both directions. WebSockets payload data is UTF-8
encoded so in order to transport binary data it must use an encoding
that can be encapsulated within UTF-8. websockify uses base64 to encode
all traffic to and from the client. Also, WebSockets traffic starts
with '\0' (0) and ends with '\xff' (255). Some buffering is done in
case the data from the client is not a full WebSockets frame (i.e.
does not end in 255).


### Websock Javascript library

The `include/websock.js` Javascript library library provides a Websock
object that is similar to the standard WebSocket object but Websock
enables communication with raw TCP sockets (i.e. the binary stream)
via websockify. This is accomplished by base64 encoding the data
stream between Websock and websockify.

Websock has built-in receive queue buffering; the message event
does not contain actual data but is simply a notification that
there is new data available. Several rQ* methods are available to
read binary data off of the receive queue.

See the "Wrap a Program" section below for an example of using Websock
and websockify as a browser telnet client (`wstelnet.html`).


### Additional websockify features

These are not necessary for the basic operation.

* Daemonizing: When the `-D` option is specified, websockify runs
  in the background as a daemon process.

* SSL (the wss:// WebSockets URI): This is detected automatically by
  websockify by sniffing the first byte sent from the client and then
  wrapping the socket if the data starts with '\x16' or '\x80'
  (indicating SSL).

* Flash security policy: websockify detects flash security policy
  requests (again by sniffing the first packet) and answers with an
  appropriate flash security policy response (and then closes the
  port). This means no separate flash security policy server is needed
  for supporting the flash WebSockets fallback emulator.

* Session recording: This feature that allows recording of the traffic
  sent and received from the client to a file using the `--record`
  option.

* Mini-webserver: websockify can detect and respond to normal web
  requests on the same port as the WebSockets proxy and Flash security
  policy. This functionality is activate with the `--web DIR` option
  where DIR is the root of the web directory to serve.

* Wrap a program: see the "Wrap a Program" section below.


### Implementations of websockify

The primary implementation of websockify is in python. There are also
alternative implementations in the `other/` subdirectory.

Here is the feature support matrix for the the websockify
implementations:

<table>
    <tr>
        <th>Program</th>
        <th>websockify</th>
        <th>other/websockify</th>
        <th>other/websockify.js</th>
        <th>other/kumina</th>
    </tr> <tr>
        <th>Language</th>
        <td>python</td>
        <td>C</td>
        <td>Node (node.js)</td>
        <td>C</td>
    </tr> <tr>
        <th>Multiproc</th>
        <td>yes</td>
        <td>yes</td>
        <td>yes</td>
        <td>no</td>
    </tr> <tr>
        <th>Daemon</th>
        <td>yes</td>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
    </tr> <tr>
        <th>SSL wss</th>
        <td>yes 1</td>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
    </tr> <tr>
        <th>Flash Policy Server</th>
        <td>yes</td>
        <td>yes</td>
        <td>no</td>
        <td>yes</td>
    </tr> <tr>
        <th>Session Record</th>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
        <td>no</td>
    </tr> <tr>
        <th>Web Server</th>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
        <td>no</td>
    </tr> <tr>
        <th>Program Wrap</th>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
        <td>no</td>
    </tr> <tr>
        <th>Multiple Targets</th>
        <td>no</td>
        <td>no</td>
        <td>no</td>
        <td>yes</td>
    </tr> <tr>
        <th>Hixie 75</th>
        <td>yes</td>
        <td>yes</td>
        <td>yes</td>
        <td>no</td>
    </tr> <tr>
        <th>Hixie 76</th>
        <td>yes</td>
        <td>yes</td>
        <td>yes</td>
        <td>yes</td>
    </tr> <tr>
        <th>IETF/HyBi 07</th>
        <td>yes</td>
        <td>no</td>
        <td>no</td>
        <td>no</td>
    </tr>
</table>


* Note 1: to use SSL/wss with python 2.5 or older, see the following
  section on *Building the Python ssl module*.


### Wrap a Program

In addition to proxying from a source address to a target address
(which may be on a different system), websockify has the ability to
launch a program on the local system and proxy WebSockets traffic to
a normal TCP port owned/bound by the program.

The is accomplished with a small LD_PRELOAD library (`rebind.so`)
which intercepts bind() system calls by the program. The specified
port is moved to a new localhost/loopback free high port. websockify
then proxies WebSockets traffic directed to the original port to the
new (moved) port of the program.

The program wrap mode is invoked by replacing the target with `--`
followed by the program command line to wrap.

    `./websockify 2023 -- PROGRAM ARGS`

The `--wrap-mode` option can be used to indicate what action to take
when the wrapped program exits or daemonizes.

Here is an example of using websockify to wrap the vncserver command
(which backgrounds itself) for use with
[noVNC](https://github.com/kanaka/noVNC):

    `./websockify 5901 --wrap-mode=ignore -- vncserver -geometry 1024x768 :1`

Here is an example of wrapping telnetd (from krb5-telnetd).telnetd
exits after the connection closes so the wrap mode is set to respawn
the command:

    `sudo ./websockify 2023 --wrap-mode=respawn -- telnetd -debug 2023`

The `wstelnet.html` page demonstrates a simple WebSockets based telnet
client.


### Building the Python ssl module (for python 2.5 and older)

* Install the build dependencies. On Ubuntu use this command:

    `sudo aptitude install python-dev bluetooth-dev`

* Download, build the ssl module and symlink to it:

    `cd websockify/`

    `wget http://pypi.python.org/packages/source/s/ssl/ssl-1.15.tar.gz`

    `tar xvzf ssl-1.15.tar.gz`

    `cd ssl-1.15`

    `make`

    `cd ../`

    `ln -sf ssl-1.15/build/lib.linux-*/ssl ssl`

