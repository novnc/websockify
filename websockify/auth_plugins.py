class BasePlugin(object):
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

        super(AuthenticationError, self).__init__('%s %s' % (self.code, log_msg))


class InvalidOriginError(AuthenticationError):
    def __init__(self, expected, actual):
        self.expected_origin = expected
        self.actual_origin = actual

        super(InvalidOriginError, self).__init__(
            response_msg='Invalid Origin',
            log_msg="Invalid Origin Header: Expected one of "
                    "%s, got '%s'" % (expected, actual))


class BasicHTTPAuth(object):
    def __init__(self, src=None):
        self.src = src

    def authenticate(self, headers, target_host, target_port):
        import base64

        auth_header = headers.get('Authorization')
        if auth_header:
            if not auth_header.startswith('Basic '):
                raise AuthenticationError(response_code=403)

            try:
                user_pass_raw = base64.b64decode(auth_header[6:])
            except TypeError:
                raise AuthenticationError(response_code=403)

            user_pass = user_pass_raw.split(':', 1)
            if len(user_pass) != 2:
                raise AuthenticationError(response_code=403)

            if not self.validate_creds:
                raise AuthenticationError(response_code=403)

        else:
            raise AuthenticationError(response_code=401,
                                      response_headers={'WWW-Authenticate': 'Basic realm="Websockify"'})

    def validate_creds(username, password):
        if '%s:%s' % (username, password) == self.src:
            return True
        else:
            return False

class ExpectOrigin(object):
    def __init__(self, src=None):
        if src is None:
            self.source = []
        else:
            self.source = src.split()

    def authenticate(self, headers, target_host, target_port):
        origin = headers.get('Origin', None)
        if origin is None or origin not in self.source:
            raise InvalidOriginError(expected=self.source, actual=origin)
