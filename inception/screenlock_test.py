'''
Created on Jan 30, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from inception import screenlock, settings, util
import inception.settings
import imp
import os
import unittest


class TestScreenlock(unittest.TestCase):


    def setUp(self):
        self.samples = []
        self.tests = None
        for root, dirs, files in os.walk('../samples'): #@UnusedVariable
            for name in files:
                filepath = os.path.join(root, name)
                mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])
                if file_ext == '.py':
                    util.msg('*', 'Added sample {0}'.format(mod_name))
                    self.samples.append((mod_name, filepath))


    def tearDown(self):
        pass


    def test_screenlock(self):
        for sample in self.samples:
            settings = imp.reload(inception.settings)
            settings.startaddress = 0x00000000
            mod_name = sample[0]
            filepath = sample[1]
            util.msg('T', 'Testing sample {0}'.format(mod_name))
            try:
                module = imp.load_source(mod_name, filepath)
            except ImportError:
                assert(module)
            settings.filemode = True
            settings.filename = '../samples/' + mod_name + '.bin'
            foundtarget = False
            for target in settings.targets:
                if target['OS'] == module.OS:
                    foundtarget = [target]
            assert(foundtarget)
            util.msg('T', 'Found target: {0}'.format(foundtarget[0]['OS']))
            address, page = screenlock.attack(foundtarget)
            self.assertEqual(address & 0x00000fff, module.offset)
            self.assertEqual(page, module.page)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_screenlock']
    unittest.main()