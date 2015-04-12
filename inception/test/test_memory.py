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

Created on Aug 22, 2014

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from collections import UserDict
import os
import sys
import unittest

from _pyio import StringIO
from inception import memory
from inception.interfaces import file as interface
from inception.memory import Target, Signature, Chunk


# Target template
targets = [
    Target(
        name='find',
        note=None,
        signatures=[
            Signature(
                os=None,
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x2a0],
                chunks=[
                    Chunk(
                        chunk=0x9782440e1b5939ff,
                        chunkoffset=0x00,
                        patch=0x00,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='findall',
        note=None,
        signatures=[
            Signature(
                os=None,
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x031],
                chunks=[
                    Chunk(
                        chunk=0x00,
                        chunkoffset=0x00,
                        patch=0x00,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='findtag',
        note=None,
        signatures=[
            Signature(
                os='a',
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xea0],
                chunks=[
                    Chunk(
                        chunk=0x18b804,
                        chunkoffset=0x00,
                        patch=0x00,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='b',
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=True,
                offsets=[0x5b0],
                chunks=[
                    Chunk(
                        chunk=0xffff8b,
                        chunkoffset=0x00,
                        patch=0x00,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='c',
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xc20],
                chunks=[
                    Chunk(
                        chunk=0x8b0283,
                        chunkoffset=0x00,
                        patch=0x00,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='patch',
        note=None,
        signatures=[
            Signature(
                os=None,
                os_versions=[],
                os_architectures=['x86', 'x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x031],
                chunks=[
                    Chunk(
                        chunk=0x00,
                        chunkoffset=0x00,
                        patch=0xdeadbeef,
                        patchoffset=0x00)
                    ]
                )
            ]
        )
    ]


class TestMemory(unittest.TestCase):

    def setUp(self):
        self.opts = UserDict()
        self.opts.filename = os.path.join(
            os.path.dirname(__file__),
            'samples/ubuntu-11.10-x86-0xbaf.bin')
        self.opts.interface = 'file'
        self.opts.dry_run = True
        self.opts.size = None
        self.opts.address = None
        self.opts.verbose = None
        self.opts.list_targets = None
        self.tests = None
        self.module = UserDict()
        self.module.IS_INTRUSIVE = False

    def tearDown(self):
        pass

    def test_find(self):
        target = targets[0]
        sys.stdout = StringIO()  # Suppress output
        device, memsize = interface.initialize(self.opts, self.module)
        memspace = memory.MemorySpace(device, memsize)
        address, signature, offset = memspace.find(target)
        sys.stdout = sys.__stdout__  # Restore output
        self.assertEqual(address, 672)
        self.assertEqual(signature, target.signatures[0])
        self.assertEqual(offset, target.signatures[0].offsets[0])

    def test_findall(self):
        target = targets[1]
        sys.stdout = StringIO()  # Suppress output
        device, memsize = interface.initialize(self.opts, self.module)
        memspace = memory.MemorySpace(device, memsize)
        results = memspace.find(target, findall=True)
        sys.stdout = sys.__stdout__  # Restore output
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0][0], 49)
        self.assertEqual(results[3][0], 16433)
        for result in results:
            self.assertEqual(result[1], target.signatures[0])

    def test_findtag(self):
        target = targets[2]
        sys.stdout = StringIO()  # Suppress output
        device, memsize = interface.initialize(self.opts, self.module)
        memspace = memory.MemorySpace(device, memsize)
        results = memspace.find(target, findtag=True)
        sys.stdout = sys.__stdout__  # Restore output
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1][1], targets[2].signatures[1])

    def test_patch(self):
        target = targets[3]
        sig = target.signatures[0]
        sys.stdout = StringIO()  # Suppress output
        device, memsize = interface.initialize(self.opts, self.module)
        device.dry_run = False
        memspace = memory.MemorySpace(device, memsize)
        address = 0x00000042
        read = memspace.read(address, 4)
        memspace.patch(address, sig)
        sys.stdout = sys.__stdout__  # Restore output
        read_back = memspace.read(address, 4)
        # print(read_back)
        self.assertEqual(sig.chunks[0].patch, read_back)
        memspace.write(address, read)
        read_back = memspace.read(address, 4)
        # print(read_back)
        self.assertEqual(read, read_back)


if __name__ == "__main__":
    unittest.main()
