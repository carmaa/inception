'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2013  Carsten Maartmann-Moe

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
from _pyio import StringIO
from inception import memory, cfg
from inception.modules import unlock
from inception.interfaces import file as interface
from os import path
import imp
import os
import sys
import unittest
import importlib
from collections import UserDict


class TestUnlock(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.opts = UserDict()
        self.opts.dry_run = True
        self.opts.size = None
        self.opts.address = None
        self.opts.verbose = None
        self.opts.list_targets = None
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
            cfg.startaddress = 0x00000000
            mod_name = sample[0]
            # print(mod_name)
            filepath = sample[1]
            try:
                module = importlib.machinery.SourceFileLoader(mod_name, filepath).load_module()
            except ImportError:
                assert(module)
            self.opts.interface = 'file'
            self.opts.filename = path.join(path.dirname(__file__), 'samples/') + mod_name + '.bin'
            foundtarget = False
            for i, target in enumerate(unlock.targets, 1):
                if target.signatures[0].os == module.OS:
                    foundtarget = [target]
                    self.opts.target_number = i
            # print(module.OS)
            self.assertTrue(foundtarget)
            self.assertIsNotNone(self.opts.target_number)
            sys.stdout = StringIO() # Suppress output
            device, memsize = interface.initialize(self.opts)
            memspace = memory.MemorySpace(device, memsize)
            address, page = unlock.run(self.opts, memspace)
            sys.stdout = sys.__stdout__ # Restore output
            # print(address & 0x00000fff)
            # print(module.offset)
            #self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    unittest.main()
