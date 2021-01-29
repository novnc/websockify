# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright(c) 2015 Red Hat, Inc All Rights Reserved.
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

""" Unit tests for websocketproxy """

import sys
import unittest
import unittest
import socket
from io import StringIO
from io import BytesIO
from unittest.mock import patch, MagicMock

from jwcrypto import jwt

from websockify import websocketproxy
from websockify import token_plugins
from websockify import auth_plugins


class FakeSocket(object):
    def __init__(self, data=b''):
        self._data = data

    def recv(self, amt, flags=None):
        res = self._data[0:amt]
        if not (flags & socket.MSG_PEEK):
            self._data = self._data[amt:]

        return res

    def makefile(self, mode='r', buffsize=None):
        if 'b' in mode:
            return BytesIO(self._data)
        else:
            return StringIO(self._data.decode('latin_1'))


class FakeServer(object):
    class EClose(Exception):
        pass

    def __init__(self):
        self.token_plugin = None
        self.auth_plugin = None
        self.wrap_cmd = None
        self.ssl_target = None
        self.unix_target = None

class ProxyRequestHandlerTestCase(unittest.TestCase):
    def setUp(self):
        super(ProxyRequestHandlerTestCase, self).setUp()
        self.handler = websocketproxy.ProxyRequestHandler(
            FakeSocket(), "127.0.0.1", FakeServer())
        self.handler.path = "https://localhost:6080/websockify?token=blah"
        self.handler.headers = None
        patch('websockify.websockifyserver.WebSockifyServer.socket').start()

    def tearDown(self):
        patch.stopall()
        super(ProxyRequestHandlerTestCase, self).tearDown()

    def test_get_target(self):
        class TestPlugin(token_plugins.BasePlugin):
            def lookup(self, token):
                return ("some host", "some port")

        host, port = self.handler.get_target(
            TestPlugin(None))

        self.assertEqual(host, "some host")
        self.assertEqual(port, "some port")

    def test_get_target_unix_socket(self):
        class TestPlugin(token_plugins.BasePlugin):
            def lookup(self, token):
                return ("unix_socket", "/tmp/socket")

        _, socket = self.handler.get_target(
            TestPlugin(None))

        self.assertEqual(socket, "/tmp/socket")

    def test_get_target_raises_error_on_unknown_token(self):
        class TestPlugin(token_plugins.BasePlugin):
            def lookup(self, token):
                return None

        with self.assertRaises(FakeServer.EClose):
            self.handler.get_target(TestPlugin(None))

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_token_plugin(self):
        class TestPlugin(token_plugins.BasePlugin):
            def lookup(self, token):
                return (self.source + token).split(',')

        self.handler.server.token_plugin = TestPlugin("somehost,")
        self.handler.validate_connection()

        self.assertEqual(self.handler.server.target_host, "somehost")
        self.assertEqual(self.handler.server.target_port, "blah")

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_asymmetric_jws_token_plugin(self):
        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/public.pem")
        self.handler.validate_connection()

        self.assertEqual(self.handler.server.target_host, "remote_host")
        self.assertEqual(self.handler.server.target_port, "remote_port")

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_asymmetric_jws_token_plugin_with_illigal_key_exception(self):
        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("wrong.pub")
        with self.assertRaises(self.handler.server.EClose):
            self.handler.validate_connection()


    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    @patch('time.time')
    def test_jwt_valid_time(self, mock_time):
        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())
        mock_time.return_value = 150

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/public.pem")
        self.handler.validate_connection()

        self.assertEqual(self.handler.server.target_host, "remote_host")
        self.assertEqual(self.handler.server.target_port, "remote_port")

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    @patch('time.time')
    def test_jwt_early_time(self, mock_time):
        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())
        mock_time.return_value = 50

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/public.pem")
        with self.assertRaises(self.handler.server.EClose):
            self.handler.validate_connection()

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    @patch('time.time')
    def test_jwt_late_time(self, mock_time):
        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())
        mock_time.return_value = 250

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/public.pem")
        with self.assertRaises(self.handler.server.EClose):
            self.handler.validate_connection()


    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_symmetric_jws_token_plugin(self):
        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwt.JWK()
        key.import_key(kty="oct",k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/symmetric.key")
        self.handler.validate_connection()

        self.assertEqual(self.handler.server.target_host, "remote_host")
        self.assertEqual(self.handler.server.target_port, "remote_port")

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_symmetric_jws_token_plugin_with_illigal_key_exception(self):
        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwt.JWK()
        key.import_key(kty="oct",k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)
        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwt_token.serialize())

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("wrong_sauce")
        self.assertRaises(self.handler.server.EClose, 
                        self.handler.validate_connection)

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_asymmetric_jwe_token_plugin(self):
        private_key = jwt.JWK()
        public_key = jwt.JWK()
        private_key_data = open("./tests/fixtures/private.pem", "rb").read()
        public_key_data = open("./tests/fixtures/public.pem", "rb").read()
        private_key.import_from_pem(private_key_data)
        public_key.import_from_pem(public_key_data)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(private_key)
        jwe_token = jwt.JWT(header={"alg": "RSA1_5", "enc": "A256CBC-HS512"},
                    claims=jwt_token.serialize())
        jwe_token.make_encrypted_token(public_key)

        self.handler.path = "https://localhost:6080/websockify?token={jwt_token}".format(jwt_token=jwe_token.serialize())

        self.handler.server.token_plugin = token_plugins.JWTTokenApi("./tests/fixtures/private.pem")
        self.handler.validate_connection()

        self.assertEqual(self.handler.server.target_host, "remote_host")
        self.assertEqual(self.handler.server.target_port, "remote_port")

    @patch('websockify.websocketproxy.ProxyRequestHandler.send_auth_error', MagicMock())
    def test_auth_plugin(self):
        class TestPlugin(auth_plugins.BasePlugin):
            def authenticate(self, headers, target_host, target_port):
                if target_host == self.source:
                    raise auth_plugins.AuthenticationError(response_msg="some_error")

        self.handler.server.auth_plugin = TestPlugin("somehost")
        self.handler.server.target_host = "somehost"
        self.handler.server.target_port = "someport"

        with self.assertRaises(auth_plugins.AuthenticationError):
            self.handler.auth_connection()

        self.handler.server.target_host = "someotherhost"
        self.handler.auth_connection()

