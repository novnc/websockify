class BasePlugin(object):
    def __init__(self, src=None):
        self.source = src

    def authenticate(self, headers, target_host, target_port):
        pass


class AuthenticationError(Exception):
    pass


class InvalidOriginError(AuthenticationError):
    def __init__(self, expected, actual):
        self.expected_origin = expected
        self.actual_origin = actual

        super(InvalidOriginError, self).__init__(
            "Invalid Origin Header: Expected one of "
            "%s, got '%s'" % (expected, actual))


class ExpectOrigin(object):
    def __init__(self, src=None):
        if src is None:
            self.source = []
        else:
            self.source = src.split()

    def authenticate(self, headers, target_host, target_port):
        origin = headers.getheader('Origin', None)
        if origin is None or origin not in self.source:
            raise InvalidOriginError(expected=self.source, actual=origin)
