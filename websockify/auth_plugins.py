import logging
logger = logging.getLogger(__name__)

try:
    from passlib.apache import HtpasswdFile
except ImportError as e:
    HtpasswdFile: None


class BasePlugin():
    def __init__(self, src=None):
        self.source = src

    def authenticate(self, headers, target_host, target_port):
        pass


class AuthenticationError(Exception):
    def __init__(self, log_msg=None, response_code=403, response_headers={}, response_msg=None):
        self.code = response_code
        self.headers = response_headers
        self.msg = response_msg

        if log_msg is None:
            log_msg = response_msg

        super().__init__('%s %s' % (self.code, log_msg))


class InvalidOriginError(AuthenticationError):
    def __init__(self, expected, actual):
        self.expected_origin = expected
        self.actual_origin = actual

        super().__init__(
            response_msg='Invalid Origin',
            log_msg="Invalid Origin Header: Expected one of "
                    "%s, got '%s'" % (expected, actual))


class BasicHTTPAuth():
    """Verifies Basic Auth headers. Specify src as username:password"""

    def __init__(self, src=None):
        self.src = src

    def authenticate(self, headers, target_host, target_port):
        import base64
        auth_header = headers.get('Authorization')
        if auth_header:
            if not auth_header.startswith('Basic '):
                self.auth_error()

            try:
                user_pass_raw = base64.b64decode(auth_header[6:])
            except TypeError:
                self.auth_error()

            try:
                # http://stackoverflow.com/questions/7242316/what-encoding-should-i-use-for-http-basic-authentication
                user_pass_as_text = user_pass_raw.decode('ISO-8859-1')
            except UnicodeDecodeError:
                self.auth_error()

            user_pass = user_pass_as_text.split(':', 1)
            if len(user_pass) != 2:
                self.auth_error()

            if not self.validate_creds(*user_pass):
                self.demand_auth()

        else:
            self.demand_auth()

    def validate_creds(self, username, password):
        if '%s:%s' % (username, password) == self.src:
            return True
        else:
            return False

    def auth_error(self):
        raise AuthenticationError(response_code=403)

    def demand_auth(self):
        raise AuthenticationError(response_code=401,
                                  response_headers={'WWW-Authenticate': 'Basic realm="Websockify"'})

class HtpasswdAuth(BasicHTTPAuth):
    """Verifies Basic Auth headers against a htpasswd database. Specify src as the path to the htpasswd file"""

    def __init__(self, src=None):
        self.src = src
        if HtpasswdFile is None:
            logging.error("Class ''HtpasswdFile' from libpass (passlib.apache), is not initialized, verify the availability of the module 'libpass'" )
            raise AuthenticationError(response_code=500, response_msg=f"Internal Server Error")

    def validate_creds(self, username, password):
        if self.src == None:
            return False
        try:
            htfile = HtpasswdFile(self.src, new=False, encoding="utf-8")
            isvalid_hash = htfile.check_password(username, password)
            if isvalid_hash == None:
                logger.warning("'%s' user not found in database." % (username))
            return isvalid_hash
        except (FileNotFoundError, PermissionError, OSError, ValueError) as e:
            logging.error("%s: %s" % (type(e).__name__, e))
            raise AuthenticationError(response_code=500, response_msg=f"Internal Server Error")
        return False

class ExpectOrigin():
    def __init__(self, src=None):
        if src is None:
            self.source = []
        else:
            self.source = src.split()

    def authenticate(self, headers, target_host, target_port):
        origin = headers.get('Origin', None)
        if origin is None or origin not in self.source:
            raise InvalidOriginError(expected=self.source, actual=origin)

class ClientCertCNAuth():
    """Verifies client by SSL certificate. Specify src as whitespace separated list of common names."""

    def __init__(self, src=None):
        if src is None:
            self.source = []
        else:
            self.source = src.split()

    def authenticate(self, headers, target_host, target_port):
        if headers.get('SSL_CLIENT_S_DN_CN', None) not in self.source:
            raise AuthenticationError(response_code=403)
