#!/usr/bin/python

'''
Display UTF-8 encoding for 0-255.'''

import sys, os, socket, ssl, time, traceback
from select import select

sys.path.insert(0,os.path.dirname(__file__) + "/../utils/")
from websocket import WebSocketServer

if __name__ == '__main__':
    for c in range(0, 256):
        print "%d: %s" % (c, repr(WebSocketServer.encode(chr(c))[1:-1]))
    #nums = "".join([chr(c) for c in range(0,256)])
    #for char in WebSocketServer.encode(nums):
    #    print "%d" % ord(char),
    #print repr(WebSocketServer.encode(nums))

