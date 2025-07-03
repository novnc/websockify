# vim: tabstop=4 shiftwidth=4 softtabstop=4

""" Unit tests for Token plugins"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from jwcrypto import jwt, jwk

try:
    import redis
except ImportError:
    redis = None

from websockify.token_plugins import parse_source_args, ReadOnlyTokenFile, JWTTokenApi, TokenRedis


class ParseSourceArgumentsTestCase(unittest.TestCase):
    def test_parameterized(self):
        params = [
            ('', ['']),
            (':', ['', '']),
            ('::', ['', '', '']),
            ('"', ['"']),
            ('""', ['""']),
            ('"""', ['"""']),
            ('"localhost"', ['localhost']),
            ('"localhost":', ['localhost', '']),
            ('"localhost"::', ['localhost', '', '']),
            ('"local:host"', ['local:host']),
            ('"local:host:"pass"', ['"local', 'host', "pass"]),
            ('"local":"host"', ['local', 'host']),
            ('"local":host"', ['local', 'host"']),
            ('localhost:6379:1:pass"word:"my-app-namespace:dev"',
             ['localhost', '6379', '1', 'pass"word', 'my-app-namespace:dev']),
        ]
        for src, args in params:
            self.assertEqual(args, parse_source_args(src))


class ReadOnlyTokenFileTestCase(unittest.TestCase):
    def test_empty(self):
        mock_source_file = MagicMock()
        mock_source_file.is_dir.return_value = False
        mock_source_file.open.return_value.__enter__.return_value.readlines.return_value = [""]

        with patch("websockify.token_plugins.Path") as mock_path:
            mock_path.return_value = mock_source_file
            plugin = ReadOnlyTokenFile('configfile')
            result = plugin.lookup('testhost')

        mock_path.assert_called_once_with('configfile')
        self.assertIsNone(result)

    def test_simple(self):
        mock_source_file = MagicMock()
        mock_source_file.is_dir.return_value = False
        mock_source_file.open.return_value.__enter__.return_value.readlines.return_value = ["testhost: remote_host:remote_port"]

        with patch("websockify.token_plugins.Path") as mock_path:
            mock_path.return_value = mock_source_file
            plugin = ReadOnlyTokenFile('configfile')
            result = plugin.lookup('testhost')

        mock_path.assert_called_once_with('configfile')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    def test_dir_with_files(self):
        mock_file1 = MagicMock()
        mock_file1.is_file.return_value = True
        mock_file1.is_dir.return_value = False
        mock_file1.open.return_value.__enter__.return_value.readlines.return_value = ["testhost1: remote_host1:remote_port1"]

        mock_file2 = MagicMock()
        mock_file2.is_file.return_value = True
        mock_file2.is_dir.return_value = False
        mock_file2.open.return_value.__enter__.return_value.readlines.return_value = ["testhost2: remote_host2:remote_port2"]

        mock_dir = MagicMock()
        mock_dir.is_dir.return_value = True
        mock_dir.is_file.return_value = False

        mock_source_dir = MagicMock()
        mock_source_dir.is_dir.return_value = True
        mock_source_dir.iterdir.return_value = [mock_file1, mock_file2, mock_dir]

        with patch("websockify.token_plugins.Path") as mock_path:
            mock_path.return_value = mock_source_dir
            plugin = ReadOnlyTokenFile('configdir')
            result1 = plugin.lookup('testhost1')
            result2 = plugin.lookup('testhost2')

        mock_path.assert_called_once_with('configdir')
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertEqual(result1, ["remote_host1", "remote_port1"])
        self.assertEqual(result2, ["remote_host2", "remote_port2"])

    def test_tabs(self):
        mock_source_file = MagicMock()
        mock_source_file.is_dir.return_value = False
        mock_source_file.open.return_value.__enter__.return_value.readlines.return_value = ["testhost:\tremote_host:remote_port"]

        with patch("websockify.token_plugins.Path") as mock_path:
            mock_path.return_value = mock_source_file
            plugin = ReadOnlyTokenFile('configfile')
            result = plugin.lookup('testhost')

        mock_path.assert_called_once_with('configfile')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")


class JWSTokenTestCase(unittest.TestCase):
    def test_asymmetric_jws_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwk.JWK()
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

        key = jwk.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    @patch('time.time')
    def test_jwt_valid_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwk.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200})
        jwt_token.make_signed_token(key)
        mock_time.return_value = 150

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    @patch('time.time')
    def test_jwt_early_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwk.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200})
        jwt_token.make_signed_token(key)
        mock_time.return_value = 50

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    @patch('time.time')
    def test_jwt_late_time(self, mock_time):
        plugin = JWTTokenApi("./tests/fixtures/public.pem")

        key = jwk.JWK()
        private_key = open("./tests/fixtures/private.pem", "rb").read()
        key.import_from_pem(private_key)
        jwt_token = jwt.JWT({"alg": "RS256"}, {'host': "remote_host", 'port': "remote_port", 'nbf': 100, 'exp': 200})
        jwt_token.make_signed_token(key)
        mock_time.return_value = 250

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    def test_symmetric_jws_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/symmetric.key")

        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwk.JWK()
        key.import_key(kty="oct", k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "remote_host")
        self.assertEqual(result[1], "remote_port")

    def test_symmetric_jws_token_plugin_with_illigal_key_exception(self):
        plugin = JWTTokenApi("wrong_sauce")

        secret = open("./tests/fixtures/symmetric.key").read()
        key = jwk.JWK()
        key.import_key(kty="oct", k=secret)
        jwt_token = jwt.JWT({"alg": "HS256"}, {'host': "remote_host", 'port': "remote_port"})
        jwt_token.make_signed_token(key)

        result = plugin.lookup(jwt_token.serialize())

        self.assertIsNone(result)

    def test_asymmetric_jwe_token_plugin(self):
        plugin = JWTTokenApi("./tests/fixtures/private.pem")

        private_key = jwk.JWK()
        public_key = jwk.JWK()
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


class TokenRedisTestCase(unittest.TestCase):
    def setUp(self):
        if redis is None:
            patcher = patch.dict(sys.modules, {'redis': MagicMock()})
            patcher.start()
            self.addCleanup(patcher.stop)

    @patch('redis.Redis')
    def test_empty(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = None

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNone(result)

    @patch('redis.Redis')
    def test_simple(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = b'{"host": "remote_host:remote_port"}'

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    @patch('redis.Redis')
    def test_json_token_with_spaces(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = b' {"host": "remote_host:remote_port"} '

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    @patch('redis.Redis')
    def test_text_token(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = b'remote_host:remote_port'

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    @patch('redis.Redis')
    def test_text_token_with_spaces(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = b' remote_host:remote_port '

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    @patch('redis.Redis')
    def test_invalid_token(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')

        instance = mock_redis.return_value
        instance.get.return_value = b'{"host": "remote_host:remote_port"   '

        result = plugin.lookup('testhost')

        instance.get.assert_called_once_with('testhost')
        self.assertIsNone(result)

    @patch('redis.Redis')
    def test_token_without_namespace(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234')
        token = 'testhost'

        def mock_redis_get(key):
            self.assertEqual(key, token)
            return b'remote_host:remote_port'

        instance = mock_redis.return_value
        instance.get = mock_redis_get

        result = plugin.lookup(token)

        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    @patch('redis.Redis')
    def test_token_with_namespace(self, mock_redis):
        plugin = TokenRedis('127.0.0.1:1234:::namespace')
        token = 'testhost'

        def mock_redis_get(key):
            self.assertEqual(key, "namespace:" + token)
            return b'remote_host:remote_port'

        instance = mock_redis.return_value
        instance.get = mock_redis_get

        result = plugin.lookup(token)

        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'remote_host')
        self.assertEqual(result[1], 'remote_port')

    def test_src_only_host(self):
        plugin = TokenRedis('127.0.0.1')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_port(self):
        plugin = TokenRedis('127.0.0.1:1234')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 1234)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_port_db(self):
        plugin = TokenRedis('127.0.0.1:1234:2')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 1234)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_port_db_pass(self):
        plugin = TokenRedis('127.0.0.1:1234:2:verysecret')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 1234)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, 'verysecret')
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_port_db_pass_namespace(self):
        plugin = TokenRedis('127.0.0.1:1234:2:verysecret:namespace')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 1234)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, 'verysecret')
        self.assertEqual(plugin._namespace, "namespace:")

    def test_src_with_host_empty_port_empty_db_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1:::verysecret')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, 'verysecret')
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_empty_db_empty_pass_empty_namespace(self):
        plugin = TokenRedis('127.0.0.1::::')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_empty_db_empty_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1:::')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_empty_db_no_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1::')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_no_db_no_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1:')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_empty_db_empty_pass_namespace(self):
        plugin = TokenRedis('127.0.0.1::::namespace')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "namespace:")

    def test_src_with_host_empty_port_empty_db_empty_pass_nested_namespace(self):
        plugin = TokenRedis('127.0.0.1::::"ns1:ns2"')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "ns1:ns2:")

    def test_src_with_host_empty_port_db_no_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1::2')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_port_empty_db_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1:1234::verysecret')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 1234)
        self.assertEqual(plugin._db, 0)
        self.assertEqual(plugin._password, 'verysecret')
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_db_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1::2:verysecret')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, 'verysecret')
        self.assertEqual(plugin._namespace, "")

    def test_src_with_host_empty_port_db_empty_pass_no_namespace(self):
        plugin = TokenRedis('127.0.0.1::2:')

        self.assertEqual(plugin._server, '127.0.0.1')
        self.assertEqual(plugin._port, 6379)
        self.assertEqual(plugin._db, 2)
        self.assertEqual(plugin._password, None)
        self.assertEqual(plugin._namespace, "")
