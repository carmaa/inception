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
from inception.interfaces.firewire import FireWire
from inception import cfg
import unittest


class TestUtil(unittest.TestCase):


    def setUp(self):
        cfg.os = cfg.LINUX # supress OS X error message
        self.fw = FireWire(0)


    def tearDown(self):
        pass


    def test_init_OUI(self):
        self.assertIsInstance(self.fw.oui, dict)
        # Test a couple of OUIs
        self.assertEqual(self.fw.resolve_oui(0x03), 'XEROX CORPORATION')
        self.assertEqual(self.fw.resolve_oui(0xE0C1), 
                         'MEMOREX TELEX JAPAN, LTD.')
        self.assertEqual(self.fw.resolve_oui(0xFCFBFB), 'Cisco Systems')
    


if __name__ == "__main__":
    unittest.main()
