# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright(c)2013 NTT corp. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" Unit tests for websocket """
import errno
import os
import logging
import select
import shutil
import socket
import ssl
import stubout
import sys
import tempfile
import unittest
from ssl import SSLError
from websockify import websocket as websocket
from SimpleHTTPServer import SimpleHTTPRequestHandler


class MockConnection(object):
    def __init__(self, path):
        self.path = path

    def makefile(self, mode='r', bufsize=-1):
        return open(self.path, mode, bufsize)


class WebSocketTestCase(unittest.TestCase):

    def _init_logger(self, tmpdir):
        name = 'websocket-unittest'
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = True
        filename = "%s.log" % (name)
        handler = logging.FileHandler(filename)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    def setUp(self):
        """Called automatically before each test."""
        super(WebSocketTestCase, self).setUp()
        self.stubs = stubout.StubOutForTesting()
        # Temporary dir for test data
        self.tmpdir = tempfile.mkdtemp()
        # Put log somewhere persistent
        self._init_logger('./')
        # Mock this out cause it screws tests up
        self.stubs.Set(os, 'chdir', lambda *args, **kwargs: None)
        self.server = self._get_websockserver(daemon=True,
                                              ssl_only=False)
        self.soc = self.server.socket('localhost')

    def tearDown(self):
        """Called automatically after each test."""
        self.stubs.UnsetAll()
        shutil.rmtree(self.tmpdir)
        super(WebSocketTestCase, self).tearDown()

    def _get_websockserver(self, **kwargs):
        return websocket.WebSocketServer(listen_host='localhost',
                                         listen_port=80,
                                         key=self.tmpdir,
                                         web=self.tmpdir,
                                         record=self.tmpdir,
                                         **kwargs)        

    def _mock_os_open_oserror(self, file, flags):
        raise OSError('')

    def _mock_os_close_oserror(self, fd):
        raise OSError('')

    def _mock_os_close_oserror_EBADF(self, fd):
        raise OSError(errno.EBADF, '')

    def _mock_socket(self, *args, **kwargs):
        return self.soc

    def _mock_select(self, rlist, wlist, xlist, timeout=None):
        return '_mock_select'

    def _mock_select_exception(self, rlist, wlist, xlist, timeout=None):
        raise Exception

    def _mock_select_keyboardinterrupt(self, rlist, wlist,
                                       xlist, timeout=None):
        raise KeyboardInterrupt

    def _mock_select_systemexit(self, rlist, wlist, xlist, timeout=None):
        sys.exit()

    def test_daemonize_error(self):
        soc = self._get_websockserver(daemon=True, ssl_only=1, idle_timeout=1)
        self.stubs.Set(os, 'fork', lambda *args: None)
        self.stubs.Set(os, 'setsid', lambda *args: None)
        self.stubs.Set(os, 'close', self._mock_os_close_oserror)
        self.assertRaises(OSError, soc.daemonize, keepfd=None, chdir='./')

    def test_daemonize_EBADF_error(self):
        soc = self._get_websockserver(daemon=True, ssl_only=1, idle_timeout=1)
        self.stubs.Set(os, 'fork', lambda *args: None)
        self.stubs.Set(os, 'setsid', lambda *args: None)
        self.stubs.Set(os, 'close', self._mock_os_close_oserror_EBADF)
        self.stubs.Set(os, 'open', self._mock_os_open_oserror)
        self.assertRaises(OSError, soc.daemonize, keepfd=None, chdir='./')

    def test_decode_hybi(self):
        soc = self._get_websockserver(daemon=False, ssl_only=1, idle_timeout=1)
        self.assertRaises(Exception, soc.decode_hybi, 'a' * 128,
                          base64=True)

    def test_do_websocket_handshake(self):
        soc = self._get_websockserver(daemon=True, ssl_only=0, idle_timeout=1)
        soc.scheme = 'scheme'
        headers = {'Sec-WebSocket-Protocol': 'binary',
                   'Sec-WebSocket-Version': '7',
                   'Sec-WebSocket-Key': 'foo'}
        soc.do_websocket_handshake(headers, '127.0.0.1')

    def test_do_handshake(self):
        soc = self._get_websockserver(daemon=True, ssl_only=0, idle_timeout=1)
        self.stubs.Set(select, 'select', self._mock_select)
        self.stubs.Set(socket._socketobject, 'recv', lambda *args: 'mock_recv')
        self.assertRaises(Exception, soc.do_handshake, self.soc, '127.0.0.1')

    def test_do_handshake_ssl_error(self):
        soc = self._get_websockserver(daemon=True, ssl_only=0, idle_timeout=1)

        def _mock_wrap_socket(*args, **kwargs):
            from ssl import SSLError
            raise SSLError('unit test exception')

        self.stubs.Set(select, 'select', self._mock_select)
        self.stubs.Set(socket._socketobject, 'recv', lambda *args: '\x16')
        self.stubs.Set(ssl, 'wrap_socket', _mock_wrap_socket)
        self.assertRaises(SSLError, soc.do_handshake, self.soc, '127.0.0.1')

    def test_fallback_SIGCHILD(self):
        soc = self._get_websockserver(daemon=True, ssl_only=0, idle_timeout=1)
        soc.fallback_SIGCHLD(None, None)

    def test_start_server_Exception(self):
        soc = self._get_websockserver(daemon=False, ssl_only=1, idle_timeout=1)
        self.stubs.Set(websocket.WebSocketServer, 'socket', self._mock_socket)
        self.stubs.Set(websocket.WebSocketServer, 'daemonize',
                       lambda *args, **kwargs: None)
        self.stubs.Set(select, 'select', self._mock_select_exception)
        self.assertEqual(None, soc.start_server())

    def test_start_server_KeyboardInterrupt(self):
        soc = self._get_websockserver(daemon=False, ssl_only=1, idle_timeout=1)
        self.stubs.Set(websocket.WebSocketServer, 'socket', self._mock_socket)
        self.stubs.Set(websocket.WebSocketServer, 'daemonize',
                       lambda *args, **kwargs: None)
        self.stubs.Set(select, 'select', self._mock_select_keyboardinterrupt)
        self.assertEqual(None, soc.start_server())

    def test_start_server_systemexit(self):
        websocket.ssl = None
        self.stubs.Set(websocket.WebSocketServer, 'socket', self._mock_socket)
        self.stubs.Set(websocket.WebSocketServer, 'daemonize',
                       lambda *args, **kwargs: None)
        self.stubs.Set(select, 'select', self._mock_select_systemexit)
        soc = self._get_websockserver(daemon=True, ssl_only=0, idle_timeout=1,
                                      verbose=True)
        self.assertEqual(None, soc.start_server())

    def test_WSRequestHandle_do_GET_nofile(self):
        request = 'GET /tmp.txt HTTP/0.9'
        with tempfile.NamedTemporaryFile() as test_file:
            test_file.write(request)
            test_file.flush()
            test_file.seek(0)
            con = MockConnection(test_file.name)
            soc = websocket.WSRequestHandler(con, "127.0.0.1", file_only=True)
            soc.path = ''
            soc.headers = {'upgrade': ''}
            self.stubs.Set(SimpleHTTPRequestHandler, 'send_response',
                           lambda *args: None)
            soc.do_GET()
            self.assertEqual(404, soc.last_code)

    def test_WSRequestHandle_do_GET_hidden_resource(self):
        request = 'GET /tmp.txt HTTP/0.9'
        with tempfile.NamedTemporaryFile() as test_file:
            test_file.write(request)
            test_file.flush()
            test_file.seek(0)
            con = MockConnection(test_file.name)
            soc = websocket.WSRequestHandler(con, '127.0.0.1', no_parent=True)
            soc.path = test_file.name + '?'
            soc.headers = {'upgrade': ''}
            soc.webroot = 'no match startswith'
            self.stubs.Set(SimpleHTTPRequestHandler,
                           'send_response',
                           lambda *args: None)
        soc.do_GET()
        self.assertEqual(403, soc.last_code)

    def testsocket_set_keepalive_options(self):
        keepcnt = 12
        keepidle = 34
        keepintvl = 56

        sock = self.server.socket('localhost',
                                  tcp_keepcnt=keepcnt,
                                  tcp_keepidle=keepidle,
                                  tcp_keepintvl=keepintvl)

        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPCNT), keepcnt)
        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPIDLE), keepidle)
        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPINTVL), keepintvl)

        sock = self.server.socket('localhost',
                                  tcp_keepalive=False,
                                  tcp_keepcnt=keepcnt,
                                  tcp_keepidle=keepidle,
                                  tcp_keepintvl=keepintvl)

        self.assertNotEqual(sock.getsockopt(socket.SOL_TCP,
                                            socket.TCP_KEEPCNT), keepcnt)
        self.assertNotEqual(sock.getsockopt(socket.SOL_TCP,
                                            socket.TCP_KEEPIDLE), keepidle)
        self.assertNotEqual(sock.getsockopt(socket.SOL_TCP,
                                            socket.TCP_KEEPINTVL), keepintvl)
