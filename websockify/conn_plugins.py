class BasePlugin(object):
    def __init__(self, src=None):
        self.source = src

    def connect(
            self, host, port, use_ssl, unix_socket,
            sockname, query):
        """When a socket connection begins, this call receives as much
        information as possible. Especially sockname is important, because
        this allows "disconnect" to tell the connections apart."""
        pass

    def disconnect(
            self, host, port, use_ssl, unix_socket,
            sockname, query):
        """This function is called with the exact same parameters as
        "connect", but when the connection closes."""
        pass


class DebugPlugin(BasePlugin):
    """Prints out event information for connections and disconnections."""

    def connect(self, host, port, use_ssl, unix_socket, sockname, query):
        print([
            'conn_plugin.DebugPlugin connect',
            host, port, use_ssl, unix_socket,
            sockname, query,
        ])

    def disconnect(self, host, port, use_ssl, unix_socket, sockname, query):
        print([
            'conn_plugin.DebugPlugin disconnect',
            host, port, use_ssl, unix_socket,
            sockname, query,
        ])
