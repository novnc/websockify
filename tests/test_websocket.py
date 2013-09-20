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

"""Unit tests for websockify."""

import socket
import unittest
from websockify import websocket as websocket


class WebSocketTestCase(unittest.TestCase):

    def setUp(self):
        """Called automatically before each test."""
        super(WebSocketTestCase, self).setUp()

    def tearDown(self):
        """Called automatically after each test."""
        super(WebSocketTestCase, self).tearDown()

    def testsocket_set_keepalive_options(self):
        server = websocket.WebSocketServer(listen_host='localhost',
                                           listen_port=80,
                                           key='./',
                                           web='./',
                                           record='./',
                                           daemon=True,
                                           ssl_only=1)
        keepcnt = 12
        keepidle = 34
        keepintvl = 56

        sock = server.socket('localhost',
                             tcp_keepcnt=keepcnt,
                             tcp_keepidle=keepidle,
                             tcp_keepintvl=keepintvl)

        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPCNT), keepcnt)
        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPIDLE), keepidle)
        self.assertEqual(sock.getsockopt(socket.SOL_TCP,
                                         socket.TCP_KEEPINTVL), keepintvl)

        sock = server.socket('localhost',
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
