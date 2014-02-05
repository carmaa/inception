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
import inception.util
import collections
from jsonschema import validate

class InceptionTarget():

    def __init__(self, **kwargs):
        '''
        A target consisting of metadata and binary signatures.

        Mandatory Arguments:
        - signatures : The binary signatures

        Optional Keyword Arguments:
        - os: Operating system
        - os_versions: Versions of the OS targets where the sig works
        - os_architectures: Archs (e.g., x86, x64, etc.)
        - executable: The executable (exe, DLL) where the signature is located
        - executable_ver: The version of the executable
        - md5: MD5 of the executable where the signature is located
        - name: Name of the target
        - note: Text note of what the target does
        '''
        self.signatures = []
        self.os = kwargs.get('os', '')
        self.os_versions = kwargs.get('os_versions', '')
        self.os_architectures = kwargs.get('os_architectures', ['x86', 'x64'])
        self.executable = kwargs.get('executable', '')
        self.executable_ver = kwargs.get('executable_ver', '')
        self.md5 = kwargs.get('md5', '')
        self.name = kwargs.get('name', '')
        self.note = kwargs.get('note', '')

InceptionSignature = collections.namedtuple('InceptionSignature', ['offsets', 'chunks'])
class InceptionSignature():

    def __init__(self, offsets, chunks):
        self.offsets = offsets
        self._chunks = chunks

    @property
    def chunks(self):
        return self._chunks

class InceptionChunk():

    def __init__(self, chunk, internaloffset, patch, patchoffset):
        self.chunk = chunk
        self.internaloffset = internaloffset
        self.patch = patch
        self.patchoffset = patchoffset

if __name__ == '__main__':
    schema = {
        "type" : "object",
        "properties" : {
            "source" : {
                "type" : "object",
                "properties" : {
                    "name" : {"type" : "integer" }
                }
            }
        }
    }
    data ={
       "source":{
          "name":0x1,
          "bad_key":"This data is not allowed according to the schema."
       }
    }
    validate(data,schema)
    target = InceptionSignature(offsets=[0x18c], chunks={'a':0x8b})
    target.chunks.update(c=3)
    print(target.chunks.get('c'))

