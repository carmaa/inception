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

Created on Nov 4, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
import unittest
import os
from inception import settings, memdump, util
import hashlib
import sys
from _pyio import StringIO
import random
import shutil


class MemdumpTest(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.tests = None
        settings.memdump = True
        settings.filemode = True
        if not os.path.exists('temp'):
            os.makedirs('temp')
        settings.memdump_prefix = 'temp/unittest'
        for root, dirs, files in os.walk(os.path.join(os.path.dirname(__file__), '../samples/')): #@UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1]) #@UnusedVariable
                if file_ext == '.bin':
                    self.samples.append(filepath)
                    

    def tearDown(self):
        shutil.rmtree('temp')


    def test_fulldump(self):
        start = 0x00000000
        for sample in self.samples:
            #util.msg('T', 'Testing sample {0}'.format(sample))
            settings.filename = sample
            end = os.path.getsize(sample)
            sys.stdout = StringIO() # Suppress output
            memdump.dump(start, end)
            sys.stdout = sys.__stdout__ # Restore output
            output_fn = '{0}_{1}-{2}.bin'.format(settings.memdump_prefix,hex(start), hex(end))
            self.assertTrue(os.path.exists(output_fn))
            self.assertEqual(self.file_md5(sample), self.file_md5(output_fn))
        
    
    def test_upper_edge(self):
        pass
    
    
    def test_lower_edge(self):
        pass
    
    
    def test_random_read(self):
        '''
        Test a reading from a random sample, with a random size and a random
        start address
        '''
        sample = random.sample(self.samples, 1)[0]
        settings.filename = sample
        self.assertTrue(os.path.exists(sample))
        sample_size = os.path.getsize(sample)
        start = random.randrange(sample_size)
        size_range = sample_size - start
        dump_size = random.randrange(size_range)
        end = start + dump_size
        sys.stdout = StringIO() # Suppress output
        memdump.dump(start, end)
        sys.stdout = sys.__stdout__ # Restore output
        output_fn = '{0}_{1}-{2}.bin'.format(settings.memdump_prefix,hex(start), hex(end))
        self.assertTrue(os.path.exists(output_fn))
        md5 = hashlib.md5()
        f = open(sample, 'rb')
        f.seek(start)
        read = f.read(dump_size)
        md5.update(read)
        self.assertEqual(md5.digest(), self.file_md5(output_fn))
    
    
    def test_memory_avoidance(self):
        pass
    
    
    def file_md5(self, filename):
        md5 = hashlib.md5()
        with open(filename,'rb') as f: 
            for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
                md5.update(chunk)
        return md5.digest()
    

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()