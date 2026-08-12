# vim: tabstop=4 shiftwidth=4 softtabstop=4

""" Unit tests for Authentication plugins"""

from websockify.auth_plugins import BasicHTTPAuth, AuthenticationError
import unittest


class BasicHTTPAuthTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = BasicHTTPAuth('Aladdin:open sesame')

    def test_no_auth(self):
        headers = {}
        self.assertRaises(AuthenticationError, self.plugin.authenticate, headers, 'localhost', '1234')

    def test_invalid_password(self):
        headers = {'Authorization': 'Basic QWxhZGRpbjpzZXNhbWUgc3RyZWV0'}
        self.assertRaises(AuthenticationError, self.plugin.authenticate, headers, 'localhost', '1234')

    def test_valid_password(self):
        headers = {'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='}
        self.plugin.authenticate(headers, 'localhost', '1234')

    def test_garbage_auth(self):
        headers = {'Authorization': 'Basic xxxxxxxxxxxxxxxxxxxxxxxxxxxx'}
        self.assertRaises(AuthenticationError, self.plugin.authenticate, headers, 'localhost', '1234')

    def test_credentials_from_file(self):
        import os
        import tempfile

        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'Aladdin:open sesame\n')
            os.close(fd)
            plugin = BasicHTTPAuth('@' + path)
            headers = {'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='}
            plugin.authenticate(headers, 'localhost', '1234')
        finally:
            os.unlink(path)
