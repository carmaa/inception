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

Created on Nov 4, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from collections import UserDict
import hashlib
import os
import random
import shutil
import sys
import unittest

from _pyio import StringIO
from inception import memory
from inception.interfaces import file as interface
from inception.modules import dump


class MemdumpTest(unittest.TestCase):

    def setUp(self):
        self.samples = []
        self.tests = None
        self.opts = UserDict()
        self.opts.dry_run = True
        self.opts.size = None
        self.opts.address = None
        self.opts.verbose = None
        self.opts.prefix = 'temp/unittest'
        self.module = UserDict()
        self.module.IS_INTRUSIVE = False
        if not os.path.exists('temp'):
            os.makedirs('temp')
        for root, dirs, files in os.walk(
            os.path.join(
                os.path.dirname(__file__), 'samples/')):  # @UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(
                    os.path.split(filepath)[-1])  # @UnusedVariable
                if file_ext == '.bin':
                    self.samples.append(filepath)

    def tearDown(self):
        shutil.rmtree('temp')

    def test_fulldump(self):
        for sample in self.samples:
            self.opts.interface = 'file'
            self.opts.filename = sample
            sys.stdout = StringIO()  # Suppress output
            device, memsize = interface.initialize(self.opts, self.module)
            memspace = memory.MemorySpace(device, memsize)
            dump.run(self.opts, memspace)
            sys.stdout = sys.__stdout__  # Restore output
            output_fn = dump.filename
            self.assertTrue(os.path.exists(output_fn))
            self.assertEqual(self.file_md5(sample), self.file_md5(output_fn))
    
    def test_random_read(self):
        '''
        Test a reading from a random sample, with a random size and a random
        start address
        '''
        sample = random.sample(self.samples, 1)[0]
        self.opts.filename = sample
        self.assertTrue(os.path.exists(sample))
        sample_size = os.path.getsize(sample)
        self.opts.address = random.randrange(sample_size)
        size_range = sample_size - self.opts.address
        self.opts.size = random.randrange(size_range)
        sys.stdout = StringIO()  # Suppress output
        device, memsize = interface.initialize(self.opts, self.module)
        memspace = memory.MemorySpace(device, memsize)
        dump.run(self.opts, memspace)
        sys.stdout = sys.__stdout__  # Restore output
        output_fn = dump.filename
        self.assertTrue(os.path.exists(output_fn))
        md5 = hashlib.md5()
        f = open(sample, 'rb')
        f.seek(self.opts.address)
        read = f.read(self.opts.size)
        md5.update(read)
        self.assertEqual(md5.digest(), self.file_md5(output_fn))
        f.close()
    
    def file_md5(self, filename):
        md5 = hashlib.md5()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
                md5.update(chunk)
        return md5.digest()
    

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
