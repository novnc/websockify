#!/usr/bin/env python

import os

#for k,v in os.environ.items():
#    print k + " = " + v

try:
    expected = os.environ['WEBSOCKIFY_CLIENT_TOKEN']
    token = os.environ['WEBSOCKIFY_UNSAFE_TOKEN']
except:
	exit(-1)

if expected == token:
    exit(0)
else:
    exit(1)
