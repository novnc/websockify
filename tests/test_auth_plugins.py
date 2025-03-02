# vim: tabstop=4 shiftwidth=4 softtabstop=4

""" Unit tests for Authentication plugins"""

from websockify.auth_plugins import BasicHTTPAuth, HtpasswdAuth, AuthenticationError
import unittest
import tempfile


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

class HtpasswdAuthTestCase(unittest.TestCase):

    
    def setUp(self):
        self._temporary_htpasswd_file = tempfile.NamedTemporaryFile(delete=False)
        #file generated with `htpasswd -cBi test_auth_plugins.htpasswd Genie <<<"""let's make some Magic\!\nlet's make some Magic!"""; htpasswd -Bi test_auth_plugins.htpasswd Aladdin <<<"""open sesame\nopen sesame"""`
        file_content = 'Genie:$2y$05$XaF/3tlgIu6zMCkt3uHFjO8I6IIlCJHYYjryOFsec/HR3gKc79VAG\nAladdin:$2y$05$8WuTOyMgRmWQYidEUuXfE.CZsFnsdrKlR9e.5aAXlJWIID0.LUFF.\n'
        self._temporary_htpasswd_file.write(file_content.encode('utf-8'))
        self._temporary_htpasswd_file.close()
        
        self.plugin = HtpasswdAuth(self._temporary_htpasswd_file.name)

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

    def tearDown(self):
        import os
        os.remove(self._temporary_htpasswd_file.name)

