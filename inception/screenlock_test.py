'''
Created on Jan 30, 2012

@author: root
'''
import unittest
import os
import imp
from inception import screenlock, settings, util


class TestScreenlock(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.tests = None
        for root, dirs, files in os.walk('../samples'): #@UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])
                if file_ext == '.py':
                    util.msg('T', 'Added sample {0}'.format(mod_name))
                    self.samples.append((mod_name, filepath))


    def tearDown(self):
        pass


    def test_screenlock(self):
        for sample in self.samples:
            mod_name = sample[0]
            filepath = sample[1]
            util.msg('T', 'Testing sample {0}'.format(mod_name))
            try:
                module = imp.load_source(mod_name, filepath)
            except ImportError:
                assert(module)
            settings.filemode = True
            settings.filename = '../samples/' + mod_name + '.bin'
            address, page = screenlock.attack(module.signature)
            self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_screenlock']
    unittest.main()