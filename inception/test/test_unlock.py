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
from collections import UserDict
from os import path
import os
import sys
import unittest

from _pyio import StringIO
from importlib.machinery import SourceFileLoader
from inception import memory, cfg
from inception.interfaces import file as interface
from inception.modules import unlock


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
        # self.module = UserDict()
        # self.module.IS_INTRUSIVE = True
        for root, dirs, files in os.walk(
            path.join(
                os.path.dirname(__file__), 'samples/')):  # @UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(
                    os.path.split(filepath)[-1])
                if file_ext == '.py' and mod_name != '__init__':
                    self.samples.append((mod_name, filepath))

    def tearDown(self):
        pass

    def test_unlock(self):
        for sample in self.samples:
            cfg.startaddress = 0x00000000
            mod_name = sample[0]
            filepath = sample[1]
            try:
                module = SourceFileLoader(mod_name, filepath).load_module()
            except ImportError:
                assert(module)
            self.opts.interface = 'file'
            self.opts.filename = path.join(
                path.dirname(__file__), 'samples/') + mod_name + '.bin'
            foundtarget = False
            for i, target in enumerate(unlock.targets, 1):
                if target.signatures[0].os == module.OS:
                    foundtarget = [target]
                    self.opts.target_number = i
            # print(module.OS)
            self.assertTrue(foundtarget)
            self.assertIsNotNone(self.opts.target_number)
            module.IS_INTRUSIVE = True
            sys.stdout = StringIO()  # Suppress output
            device, memsize = interface.initialize(self.opts, module)
            memspace = memory.MemorySpace(device, memsize)
            address, page = unlock.run(self.opts, memspace)
            sys.stdout = sys.__stdout__  # Restore output
            # print(address & 0x00000fff)
            # print(module.offset)
            #self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    unittest.main()
