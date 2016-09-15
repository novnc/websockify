# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright(c)2013 NTT corp. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" Unit tests for websocket """
import unittest
from websockify import websocket

class HyBiEncodeDecodeTestCase(unittest.TestCase):
    def test_decode_hybi_text(self):
        buf = b'\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58'
        ws = websocket.WebSocket()
        res = ws._decode_hybi(buf)

        self.assertEqual(res['fin'], 1)
        self.assertEqual(res['opcode'], 0x1)
        self.assertEqual(res['masked'], True)
        self.assertEqual(res['length'], len(buf))
        self.assertEqual(res['payload'], b'Hello')

    def test_decode_hybi_binary(self):
        buf = b'\x82\x04\x01\x02\x03\x04'
        ws = websocket.WebSocket()
        res = ws._decode_hybi(buf)

        self.assertEqual(res['fin'], 1)
        self.assertEqual(res['opcode'], 0x2)
        self.assertEqual(res['length'], len(buf))
        self.assertEqual(res['payload'], b'\x01\x02\x03\x04')

    def test_decode_hybi_extended_16bit_binary(self):
        data = (b'\x01\x02\x03\x04' * 65)  # len > 126 -- len == 260
        buf = b'\x82\x7e\x01\x04' + data
        ws = websocket.WebSocket()
        res = ws._decode_hybi(buf)

        self.assertEqual(res['fin'], 1)
        self.assertEqual(res['opcode'], 0x2)
        self.assertEqual(res['length'], len(buf))
        self.assertEqual(res['payload'], data)

    def test_decode_hybi_extended_64bit_binary(self):
        data = (b'\x01\x02\x03\x04' * 65)  # len > 126 -- len == 260
        buf = b'\x82\x7f\x00\x00\x00\x00\x00\x00\x01\x04' + data
        ws = websocket.WebSocket()
        res = ws._decode_hybi(buf)

        self.assertEqual(res['fin'], 1)
        self.assertEqual(res['opcode'], 0x2)
        self.assertEqual(res['length'], len(buf))
        self.assertEqual(res['payload'], data)

    def test_decode_hybi_multi(self):
        buf1 = b'\x01\x03\x48\x65\x6c'
        buf2 = b'\x80\x02\x6c\x6f'

        ws = websocket.WebSocket()

        res1 = ws._decode_hybi(buf1)
        self.assertEqual(res1['fin'], 0)
        self.assertEqual(res1['opcode'], 0x1)
        self.assertEqual(res1['length'], len(buf1))
        self.assertEqual(res1['payload'], b'Hel')

        res2 = ws._decode_hybi(buf2)
        self.assertEqual(res2['fin'], 1)
        self.assertEqual(res2['opcode'], 0x0)
        self.assertEqual(res2['length'], len(buf2))
        self.assertEqual(res2['payload'], b'lo')

    def test_encode_hybi_basic(self):
        ws = websocket.WebSocket()
        res = ws._encode_hybi(0x1, b'Hello')
        expected = b'\x81\x05\x48\x65\x6c\x6c\x6f'

        self.assertEqual(res, expected)
