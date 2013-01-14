'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2012  Carsten Maartmann-Moe

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

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from _pyio import StringIO
from inception import screenlock, cfg
from os import path
import imp
import inception.cfg
import os
import sys
import unittest


class TestScreenlock(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.tests = None
        for root, dirs, files in os.walk(path.join(os.path.dirname(__file__), 'samples/')): #@UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])
                if file_ext == '.py':
                    self.samples.append((mod_name, filepath))


    def tearDown(self):
        pass


    def test_screenlock(self):
        for sample in self.samples:
            cfg = imp.reload(inception.cfg)
            cfg.startaddress = 0x00000000
            mod_name = sample[0]
            filepath = sample[1]
            try:
                module = imp.load_source(mod_name, filepath)
            except ImportError:
                assert(module)
            cfg.filemode = True
            cfg.filename = path.join(path.dirname(__file__), 'samples/') + mod_name + '.bin'
            foundtarget = False
            for target in cfg.targets:
                if target['OS'] == module.OS:
                    foundtarget = [target]
            self.assertTrue(foundtarget)
            sys.stdout = StringIO() # Suppress output
            address, page = screenlock.attack(foundtarget)
            sys.stdout = sys.__stdout__ # Restore output
            self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    unittest.main()
