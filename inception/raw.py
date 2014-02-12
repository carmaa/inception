#!/usr/bin/env python3
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

Created on Feb 3, 2014

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import util, term
import collections
from pprint import pprint


class Target():
    '''
    A target consisting of metadata and binary signatures. Can contain
    one or more signatures.

    Mandatory Arguments:
    - signatures : The binary signatures

    Optional Keyword Arguments:
    - name: Name of the target
    - note: Text note of what the target does
    '''
    def __init__(self, **kwargs):
        self.signatures = kwargs.get('signatures', [])
        self.name = kwargs.get('name', 'Not set')
        self.note = kwargs.get('note', 'None')

    def __str__(self):
        return 'Name: {0}\n' \
               'Note: {1}\n' \
               '{2}' \
               .format(self.name, self.note,
                '\n'.join(map(str, self.signatures)))


class Signature(collections.namedtuple('Signature', ['os',
                                                     'os_versions',
                                                     'os_architectures',
                                                     'executable',
                                                     'version',
                                                     'md5',
                                                     'offsets',
                                                     'chunks'])):
    '''
    A signature consisting of metadata and binary chunks of data that form
    the signature. Can contain one or more chunks.

    Mandatory Arguments:
    - offsets: The offsets within a page where the chunks should be found
    - chunks: Bits of the binary signatures

    Optional Keyword Arguments:
    - os: Operating system
    - os_versions: Versions of the OS targets where the sig works
    - os_architectures: Archs (e.g., x86, x64, etc.)
    - executable: The executable (exe, DLL) where the signature is located
    - executable_ver: The version of the executable
    - md5: MD5 of the executable where the signature is located
    '''
    def __str__(self):
        l = []
        for field in self._fields:
            name = field.capitalize().replace('_', ' ')
            value = getattr(self, field)
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            l.append('{0}: {1}'.format(name, value))
        return '\n'.join(l)


class Chunk(collections.namedtuple('Chunk', ['chunk', 'chunkoffset', 'patch',
                                             'patchoffset'])):
    '''
    A chunk of binary data to search for and a matching patch, with offsets.

    Mandatory arguments:
    - chunk: The binary string to search for
    - patch: The binary string that we're writing into memory

    Optional keyword arguments:
    - chunkoffset: An offset (in bytes) where to look for the chunk (default: 0)
    - patchoffset: An offset (in bytes) where to patch (default: 0)
    '''
    def __str__(self):
        return '\n' \
               '\tChunk: {0:#x}\n' \
               '\tOffset: {1:#x} ({1})\n' \
               '\tPatch: {2:#x}\n' \
               '\tOffset: {3:#x} ({3})\n' \
               .format(self.chunk, self.chunkoffset,
                       self.patch, self.patchoffset)
               

if __name__ == '__main__':
    target = Target(
        name='Test',
        note='Testing',
        signatures=[
            Signature(
                offsets=0x18c,
                chunks=[
                    Chunk(
                        chunk=0x01,
                        chunkoffset=0x02,
                        patch=0,
                        patchoffset=99),
                    Chunk(
                        chunk=0x01,
                        chunkoffset=0x02,
                        patch=0,
                        patchoffset=99)
                    ],
                os='Windows',
                os_versions=['SP0', 'SP1', 'SP2'],
                os_architectures=['x86', 'x64'],
                executable='explorer.exe',
                version='4.3.2',
                md5='fffffffffffffffffffffffffff')
            ])
    print(target)


