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
from inception import util, term, cfg, screenlock
from inception.exceptions import InceptionException
import collections
from pprint import pprint

class Target():
    '''
    A target consisting of metadata and binary signatures. Can contain
    one or more signatures.

    Optional keyword arguments:
    - signatures : The binary signatures
    - name: Name of the target
    - note: Text note of what the target does
    '''
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', 'Not set')
        self.note = kwargs.get('note', 'None')
        self.signatures = kwargs.get('signatures', [])


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
                                                     'tag',
                                                     'offsets',
                                                     'chunks'])):
    '''
    A signature consisting of metadata and binary chunks of data that form
    the signature. Can contain one or more chunks.

    Mandatory keyword arguments:
    - offsets: The offsets within a page where the chunks should be found
    - chunks: Bits of the binary signatures
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

    @property
    def length(self):
        '''
        Calculates the length of the total signatures in number of bytes
        '''
        value = 0
        for chunk in self.chunks:
            c = chunk.chunkoffset + len(chunk.chunk)
            if c > value:
                value = c
        return value


class Chunk(collections.namedtuple('Chunk', ['chunk', 'chunkoffset', 
                                             'patch', 'patchoffset'])):
    '''
    A chunk of binary data to search for and a matching patch, with offsets.

    Mandatory keyword arguments:
    - chunk: The (byte) string to search for
    - patch: The (byte) string that we're writing into memory
    - chunkoffset: An offset (in bytes) where to look for the chunk
    - patchoffset: An offset (in bytes) where to patch
    '''
    def __new__(cls, chunk, chunkoffset, patch, patchoffset):
        '''
        Basically ensures that all values are stored
        as python3 bytes (i.e. b'\x01', etc.) and ints
        '''
        # Check offsets
        if not (isinstance(chunkoffset, int) and isinstance(patchoffset, int)):
            raise TypeError('Offsets must be int')

        # Check chunk
        if isinstance(chunk, bytes):
            pass
        elif isinstance(chunk, int):
            chunk = util.int2bytes(chunk)
        elif isinstance(chunk, str):
            chunk = util.str2bytes(chunk)
        else:
            raise TypeError('Chunk not bytes, int or str: {0}'.format(chunk))

        # Check patch
        if isinstance(patch, bytes):
            pass
        elif isinstance(patch, int):
            patch = util.int2bytes(patch)
        elif isinstance(patch, str):
            patch = util.str2bytes(patch)
        else:
            raise TypeError('Patch not bytes, int or str: {0}'.format(patch))

        return super(Chunk, cls).__new__(
            cls, chunk, chunkoffset, patch, patchoffset)


    def __str__(self):
        return '\n' \
               '\tChunk: {0}\n' \
               '\tOffset: {1:#x} ({1})\n' \
               '\tPatch: {2}\n' \
               '\tOffset: {3:#x} ({3})\n' \
               .format(util.bytes2hexstr(self.chunk), self.chunkoffset,
                       util.bytes2hexstr(self.patch), self.patchoffset)


class MemorySpace():
    '''
    Abstraction of the memory space we are operating on.

    Mandatory arguments:
    - memory: A firewire device or a MemoryFile interface
    - memsize: The size of the memory space we're searching
    '''
    def __init__(self, memory, memsize):
        self.memory = memory
        self.memsize = memsize


    def match(self, candidate, chunks):
        '''
        Matches a candidate read from memory with the signature chunks
        '''
        for c in chunks:
            coffset = c.chunkoffset
            if c.chunk != candidate[coffset:coffset + len(c.chunk)]:
                return False
        return True


    def patch(self, address, chunks):
        '''
        Writes to the device at address, using the patches in the signature
        chunks
        '''
        success = True
        backup = self.memory.read(address, cfg.PAGESIZE)

        for c in chunks:
            if len(cfg.patchfile) > 0:
                patch = cfg.patchfile
            else:
                patch = c.patch
            if not patch:
                continue

            coffset = c.chunkoffset
            poffset = c.patchoffset
            if not poffset: 
                poffset = 0
            realaddress = address + coffset + poffset

            self.memory.write(realaddress, patch)
            read = self.memory.read(realaddress, len(patch))
            if cfg.verbose:
                # TODO: Change to .format()
                term.info('Data read back: ' + util.bytes2hexstr(read)) 
            if read != patch:
                success = False

            # Only patch once from file
            if len(cfg.patchfile) > 0:
                break

        return success, backup


    def find(self, target, findtag=False, findall=False):
        '''
        Searches through memory and returns a list of matches
        at the point in memory where the signature was found.

        Mandatory arguments:
        - target: The Target object that we are searching for

        Return:
        - A list of matches containting the address, signature, offset and
          chunks
        '''
        if findtag and findall:
            raise InceptionException('Cannot search for a tagged ' \
                'signature and all signatures at the same time')

        pageaddress = cfg.startaddress
        signatures = target.signatures
        
        # Progress bar
        prog = term.ProgressBar(max_value = self.memsize,
                                total_width = cfg.wrapper.width, 
                                print_data = cfg.verbose)
        prog.draw()

        try:
            # Build a batch of read requests of the form: [(addr1, len1), ...]
            # and a corresponding match vector: [(chunk1, patchoffset1), ...]
            j = 0
            count = 0
            cand = b'\x00'
            r = [] # Read vector
            p = [] # Match vector
            z = [] # Vector to store matches
            while pageaddress < self.memsize:
                
                # Iterate over signatures
                for s in signatures:

                    # Iterate over offsets
                    for o in s.offsets:
                        address = pageaddress + o + cfg.PAGESIZE * j
                        r.append((address, s.length))
                        p.append(s.chunks)
                        count += 1

                        # If we have built a full vector, read from memory and
                        # compare to the corresponding signatures
                        if count == cfg.vectorsize:
                            # Read data from device
                            m = 0
                            for caddr, cand in self.memory.readv(r):
                                if self.match(cand, p[m]):
                                    # Add the data to the vector
                                    z.append((caddr, s, o, p[m]))
                                    # Return
                                    if not findtag or (findtag and s.tag):
                                        print()
                                        return z
                                m += 1                    
                            # Jump to next pages (we're finished with these)
                            mask = ~(cfg.PAGESIZE - 0x01)
                            pageaddress = address & mask

                            # If we are at the last elements in the lists, 
                            # go to the next page
                            if s == signatures[-1] and o == s.offsets[-1]:
                                pageaddress = pageaddress + cfg.PAGESIZE
                                
                            # Zero out counters and vectors
                            j = 0
                            count = 0
                            r = []
                            p = []
                            
                            # Print status
                            prog.update_amount(pageaddress, cand)
                            prog.draw()
                             
                j += 1 # Increase read request count
        
        # Catch eventual exceptions, print a newline and pass them on   
        except:
            print()
            raise
        
        # If we get here, return all found sigs
        print()    
        return z


if __name__ == '__main__':
    target = Target(
        name='Test',
        note='Testing',
        signatures=[
            Signature(
                offsets=[0x18c],
                chunks=[
                    Chunk(
                        chunk=b'\x00\x00\x00\x00\xe8',
                        chunkoffset=0,
                        patch=b'\x01\x02\x03\x04',
                        patchoffset=99),
                    Chunk(
                        chunk=0x00,
                        chunkoffset=5,
                        patch=b'\x01\x02\x03\x04',
                        patchoffset=99)
                    ],
                os='Windows',
                os_versions=['SP0', 'SP1', 'SP2'],
                os_architectures=['x86', 'x64'],
                executable='explorer.exe',
                version='4.3.2',
                md5='fffffffffffffffffffffffffff',
                tag=True)
            ])
    
    # print(target)
    # print(target.signatures[0].length)
    # print(target.signatures[0].chunks[0].chunk)
    # print(util.int2bytes(target.signatures[0].chunks[0].chunk))

    # testsig = [{'chunk': 0x01020304,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0x90,
    #                                     'patchoffset': 0x29},
    #                                    {'chunk': 0xaa, # push ebx
    #                                     'internaloffset': 0x56},
    #                                    {'chunk': 0x00, # push esi; push edi
    #                                     'internaloffset': 0x00}]

    # print(screenlock.siglen(testsig))

    memory = MemorySpace(util.MemoryFile(
        '/Users/carsten/Documents/Virtual Machines.localized/Windows 7.vmwarevm/Windows 7-Snapshot9.vmem',
        cfg.PAGESIZE), cfg.GiB)

    try:
        address, signature, offset, chunks = memory.find(target, findtag=True)[0]
        print(address)
        print(signature)
        print(offset)
        print(chunks)
    except:
        pass

    memory.patch(address, chunks)


