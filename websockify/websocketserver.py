#!/usr/bin/env python

'''
Python WebSocket server base
Copyright 2011 Joel Martin
Copyright 2016 Pierre Ossman
Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
'''

import sys

# python 3.0 differences
try:    from http.server import BaseHTTPRequestHandler, HTTPServer
except: from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from websockify.websocket import WebSocket, WebSocketWantReadError, WebSocketWantWriteError

class WebSocketRequestHandler(BaseHTTPRequestHandler):
    """WebSocket request handler base class.

    This class forms the base for a server that wishes to handle
    WebSocket requests. It functions exactly as BastHTTPRequestHandler,
    except that WebSocket requests are intercepted and the methods
    handle_upgrade() and handle_websocket() are called. The standard
    do_GET() will be called for normal requests.

    The class instance SocketClass can be overridden with the class to
    use for the WebSocket connection.
    """

    SocketClass = WebSocket

    def __init__(self, request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def handle_one_request(self):
        """Extended request handler

        This is where WebSocketRequestHandler redirects requests to the
        new methods. Any sub-classes must call this method in order for
        the calls to function.
        """
        self._real_do_GET = self.do_GET
        self.do_GET = self._websocket_do_GET
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        finally:
            self.do_GET = self._real_do_GET

    def _websocket_do_GET(self):
        # Checks if it is a websocket request and redirects
        self.do_GET = self._real_do_GET

        if (self.headers.get('upgrade') and
            self.headers.get('upgrade').lower() == 'websocket'):
            self.handle_upgrade()
        else:
            self.do_GET()

    def handle_upgrade(self):
        """Initial handler for a WebSocket request

        This method is called when a WebSocket is requested. By default
        it will create a WebSocket object and perform the negotiation.
        The WebSocket object will then replace the request object and
        handle_websocket() will be called.
        """
        websocket = self.SocketClass()
        try:
            websocket.accept(self.request, self.headers)
        except Exception:
            exc = sys.exc_info()[1]
            self.send_error(400, str(exc))
            return

        self.log_request(101)

        self.request = websocket

        # Other requests cannot follow Websocket data
        self.close_connection = True

        self.handle_websocket()

    def handle_websocket(self):
        """Handle a WebSocket connection.
        
        This is called when the WebSocket is ready to be used. A
        sub-class should perform the necessary communication here and
        return once done.
        """
        pass

class WebSocketServer(HTTPServer):
    pass
