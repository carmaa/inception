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
from inception import screenlock, settings, util
import inception.settings
import imp
import os
import unittest
import sys
from _pyio import StringIO
from os import path


class TestScreenlock(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.tests = None
        for root, dirs, files in os.walk(path.join(path.dirname(__file__), '../samples/')): #@UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])
                if file_ext == '.py':
                    #util.msg('*', 'Added sample {0}'.format(mod_name))
                    self.samples.append((mod_name, filepath))


    def tearDown(self):
        pass


    def test_screenlock(self):
        for sample in self.samples:
            settings = imp.reload(inception.settings)
            settings.startaddress = 0x00000000
            mod_name = sample[0]
            filepath = sample[1]
            #util.msg('T', 'Testing sample {0}'.format(mod_name))
            try:
                module = imp.load_source(mod_name, filepath)
            except ImportError:
                assert(module)
            settings.filemode = True
            settings.filename = path.join(path.dirname(__file__), '../samples/') + mod_name + '.bin'
            foundtarget = False
            for target in settings.targets:
                if target['OS'] == module.OS:
                    foundtarget = [target]
            self.assertTrue(foundtarget)
            #util.msg('T', 'Found target: {0}'.format(foundtarget[0]['OS']))
            sys.stdout = StringIO() # Supress output
            address, page = screenlock.attack(foundtarget)
            sys.stdout = sys.__stdout__ # Restore output
            self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    unittest.main()
