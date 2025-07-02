class BasePlugin():
    def __init__(self, handler, tsock):
        self.handler = handler
        self.tsock = tsock
    def from_client(self, s):
        return s
    def from_target(self, s):
        return s
