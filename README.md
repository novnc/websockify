## wsproxy: WebSockets-to-TCP proxy (for noVNC)

### Description

wsproxy is an application that can be run from inetd, which allows noVNC
to connect to an unmodified libvncserver. Furthermore, it makes use of
the recently added support in noVNC for file names. The file name is
used to denote the port number. Say, you connect to:

  ws://host:41337/25900

The wsproxy opens a connection to:

  vnc://host:25900/

The address to which wsproxy connects, is the same as the address to
which the client connected (using getsockname()).

### Configuration

wsproxy can be enabled by adding the following line to inetd.conf:

  41337 stream tcp nowait nobody /usr/sbin/wsproxy wsproxy 25900 25909

The two parameters of wsproxy denote the minimum and the maximum allowed
port numbers. This allows a single wsproxy instance to multiplex
connections to multiple VNC servers.
