from websockify.traffic_plugins import BasePlugin
from websockify import pyDes

class RFBDes(pyDes.des):
    def setKey(self, key):
        """RFB protocol for authentication requires client to encrypt
           challenge sent by server with password using DES method. However,
           bits in each byte of the password are put in reverse order before
           using it as encryption key."""
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7 - i)
            newkey.append(btgt)
        super(RFBDes, self).setKey(newkey)

"""Intercepts VNC traffic and injects the password from a provided token"""
class VncTokenAuthenticationTrafficPlugin(BasePlugin):
    def __init__(self, handler, tsock):
        super().__init__(handler, tsock)
        self.password = self.handler.target_attribtues["password"]
        self.client_packet_count = 0
        self.target_packet_count = 0

    def from_client(self, s):
        self.client_packet_count += 1
        if self.client_packet_count == 2:
            return None
        return s

    def from_target(self, s):
        self.target_packet_count += 1
        if self.target_packet_count == 2 and b"\x02" in s[1:]: # check if password is supported
            self.tsock.send(b'\x02')
            self.handle_auth = True
            s = None # dont forward to client
        if self.target_packet_count == 3 and self.handle_auth: # challenge
            self.handle_auth = False
            pw = (self.password + '\0' * 8)[:8]  # make sure its 8 chars long, zero padded
            des = RFBDes(pw)
            response = des.encrypt(s)
            self.tsock.send(response)
            return b'\x01\x01' # send "no auth" required to client
        return s 
