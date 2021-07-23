# vim: tabstop=4 shiftwidth=4 softtabstop=4

""" Unit tests for Token plugins"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
from jwcrypto import jwt

from websockify.token_plugins import ReadOnlyTokenFile, JWTTokenApi

class ReadOnlyTokenFileTestCase(unittest.TestCase):
    patch('os.path.isdir', MagicMock(return_value=False))
    def test_empty(self):
        plugin = ReadOnlyTokenFile('configfile')

        config = ""
        pyopen = mock_open(read_data=config)

        with patch("websockify.token_plugins.open", pyopen, create=True):
            result = plugin.lookup('testhost')

        pyopen.assert_called_once_with('configfile')
        self.assertIsNone(result)

    patch('os.path.isdir', MagicMock(return_value=False))
    def test_simple(self):
        plugin = ReadOnlyTokenFile('configfile')

        config = "testhost: remote_host:remote_port"
        pyopen = mock_open(read_data=config)

        with patch("websockify.token_plugins.open", pyopen, create=True):
            result = plugin.lookup('testhost')

        pyopen.assert_called_once_with('configfile')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    patch('os.path.isdir', MagicMock(return_value=False))
    def test_tabs(self):
        plugin = ReadOnlyTokenFile('configfile')

        config = "testhost:\tremote_host:remote_port"
        pyopen = mock_open(read_data=config)

        with patch("websockify.token_plugins.open", pyopen, create=True):
            result = plugin.lookup('testhost')

        pyopen.assert_called_once_with('configfile')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

class JWSTokenTestCase(unittest.TestCase):
    def test_asymmetric_jws_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    def test_asymmetric_jws_token_plugin_with_illigal_key_exception(self):
        plugin = JWTTokenApi("wrong.pub")

        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    @patch('time.time')
    def test_jwt_valid_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        mock_time.return_value = 150

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    @patch('time.time')
    def test_jwt_early_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        mock_time.return_value = 50

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    @patch('time.time')
    def test_jwt_late_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwt.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200 })
        jwt_token.make_signed_token(key)
        mock_time.return_value = 250

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    def test_symmetric_jws_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/symmetric.key")

        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwt.JWK()
        key.import_key(kty="oct",k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    def test_symmetric_jws_token_plugin_with_illigal_key_exception(self):
        plugin = JWTTokenApi("wrong_sauce")

        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwt.JWK()
        key.import_key(kty="oct",k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    def test_asymmetric_jwe_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/private.pem")

        private_key = jwt.JWK()
        public_key = jwt.JWK()
        private_key_data = open("./tests/fixtures/private.pem", "rb").read()
        public_key_data = open("./tests/fixtures/public.pem", "rb").read()
        private_key.import_from_pem(private_key_data)
        public_key.import_from_pem(public_key_data)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(private_key)
        jwe_token = jwt.JWT(header={"alg": "RSA-OAEP", "enc": "A256CBC-HS512"},
                    claims=jwt_token.serialize())
        jwe_token.make_encrypted_token(public_key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

