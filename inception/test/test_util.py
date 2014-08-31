'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
PCI-based and IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2014  Carsten Maartmann-Moe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created on Jan 30, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception.util import hexstr2bytes, bytes2hexstr, bytelen, int2bytes, parse_unit
import unittest


class TestUtil(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_hexstr2bytes(self):
        test1 = '0x41424344'
        test1_res = b'ABCD'
        self.assertEqual(hexstr2bytes(test1), test1_res)
        test2 = '41424344'
        self.assertRaises(BytesWarning, hexstr2bytes, test2)
        
    def test_bytes2hexstr(self):
        test1 = b'ABCD'
        test1_res = '0x41424344'
        self.assertEqual(bytes2hexstr(test1), test1_res)
        test2 = '41424344'
        self.assertRaises(BytesWarning, bytes2hexstr, test2)

    def test_bytelen(self):
        test1 = -16
        test1_res = 2
        self.assertEqual(bytelen(test1), test1_res)
        test2 = 1
        test2_res = 1
        self.assertEqual(bytelen(test2), test2_res)
        test3 = 15
        test3_res = 1
        self.assertEqual(bytelen(test3), test3_res)
        
    def test_int2bytes(self):
        test1 = -16
        self.assertRaises(TypeError, int2bytes, test1)
        test2 = 1
        test2_res = b'\x01'
        self.assertEqual(int2bytes(test2), test2_res)
        test3 = 15
        test3_res = b'\x0f'
        self.assertEqual(int2bytes(test3), test3_res)
        test4 = 256
        test4_res = b'\x01\x00'
        self.assertEqual(int2bytes(test4), test4_res)

    def test_parse_unit(self):
        test1 = '1KB'
        self.assertEqual(parse_unit(test1), 1024)
        test2 = '45MiB'
        self.assertEqual(parse_unit(test2), 47185920)
        test3 = '1337gb'
        self.assertEqual(parse_unit(test3), 1435592818688)
        test4 = '12g12gb'
        with self.assertRaises(ValueError):
            parse_unit(test4)



if __name__ == "__main__":
    unittest.main()
