#!/usr/bin/env python

import os

try:
    expected = os.environ['EXPECTED_TOKEN']
    token = os.environ['WEBSOCKIFY_UNSAFE_TOKEN']
except:
	exit(-1)

print 'expected = ' + expected
print 'token = ' + token

if expected == token:
    exit(0)
else:
    exit(1)
