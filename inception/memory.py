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

Created on Feb 3, 2014

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import collections

from inception import util, cfg, terminal
from inception.exceptions import InceptionException


term = terminal.Terminal()


class Target():
    '''
    A target consisting of metadata and binary signatures. Can contain
    one or more signatures.

    Optional keyword arguments:
    - signatures: The binary signatures
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
            .format(self.name, self.note, '\n'.join(
                    map(str, self.signatures)))


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
    - tag: Set to True if you want to stop searching when this sig is found
    - offsets: The offsets within a page where the chunks should be found
    - chunks: Bits of the binary signatures
    - os: Operating system
    - os_versions: Versions of the OS targets where the sig works
    - os_architectures: Archs (e.g., x86, x64, etc.)
    - executable: The executable (exe, DLL) where the signature is located
    - executable_ver: The version of the executable
    - md5: MD5 of the executable where the signature is located
    '''
    def __new__(cls, os, os_versions, os_architectures, executable, version,
                md5, tag, offsets, chunks):
        '''
        Checks that we have at least one offset, and that offsets are a list
        of ints
        '''
        if not offsets:
            raise TypeError('No offsets in signature (you need at least one)')

        if not all(isinstance(item, int) for item in offsets):
            raise TypeError('Offsets are not integers')

        return super(Signature, cls).__new__(
            cls, os, os_versions, os_architectures, executable, version,
            md5, tag, offsets, chunks)

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
        elif isinstance(patch, type(None)):
            pass
        else:
            raise TypeError('Patch not bytes, int, str or NoneType: {0}'
                            .format(patch))

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
    - interface: A firewire device or a MemoryInterface interface
    - memsize: The size of the memory space we're searching
    '''
    def __init__(self, interface, memsize):
        self.interface = interface
        self.memsize = memsize

    def read(self, address, numb):
        '''
        Reads numb number of bytes from the address specified.
        '''
        return self.interface.read(address, numb)

    def write(self, address, data):
        '''
        Writes len(data) of data to the specified address.
        '''
        return self.interface.write(address, data)

    def release(self):
        '''
        Releases the interface (i.e., closes it).
        '''
        return self.interface.close()

    def page_no(self, address):
        '''
        Returns the page number of a given address
        '''
        return int((address) // cfg.PAGESIZE)

    def match(self, candidate, chunks):
        '''
        Matches a candidate read from memory with the signature chunks
        '''
        for c in chunks:
            coffset = c.chunkoffset
            if c.chunk != candidate[coffset:coffset + len(c.chunk)]:
                return False
        return True

    def patch(self, address, signature):
        '''
        Writes to the device at address, using the patches in the signature
        chunks
        '''
        backup = self.interface.read(address, signature.length)
        chunks = signature.chunks
        for c in chunks:
            if not c.patch:  # If no patch is set, skip this chunk
                continue

            patch = c.patch
            coffset = c.chunkoffset
            poffset = c.patchoffset
            if not poffset:
                poffset = 0
            realaddress = address + coffset + poffset

            self.interface.write(realaddress, patch)
            read = self.interface.read(realaddress, len(patch))
            if read != patch:
                raise InceptionException('Unable to verify patch')

        return backup

    def rawfind(self, offset, data, verbose=False):
        '''
        Finds raw data at a page offset
        '''
        target = Target(
            signatures=[
                Signature(
                    offsets=[offset],
                    chunks=[
                        Chunk(
                            chunk=data,
                            chunkoffset=0,
                            patch=0,
                            patchoffset=0)
                        ],
                    os='',
                    os_versions=[],
                    os_architectures=[],
                    executable='',
                    version='',
                    md5='',
                    tag=False)
                ])
        return self.find(target, verbose=verbose)

    def find(self, target, findtag=False, findall=False, verbose=False):
        '''
        Searches through memory and returns a list of matches
        at the point in memory where the signature was found.

        Mandatory arguments:
        - target: The Target object that we are searching for

        Optional arguments:
        - findtag: True if searching for a tagged (preferred) signature
        - findall: True if searching for all signatures

        Return:
        - A list of matches containting the address, signature, and offset
        '''
        if findtag and findall:
            raise InceptionException('Cannot search for a tagged signature '
                                     'and all signatures at the same time')

        pageaddress = cfg.startaddress
        signatures = target.signatures
        
        # Progress bar
        prog = term.ProgressBar(max_value=self.memsize,
                                total_width=term.wrapper.width)
        prog.draw()

        try:
            # Build a batch of read requests of the form: [(addr1, len1), ...]
            # and a corresponding match vector: [signature1, ...]
            j = 0
            count = 0
            cand = b'\x00'
            r = []  # Read vector
            p = []  # Match vector
            z = []  # Vector to store matches (result vector)
            while pageaddress < self.memsize:
                
                # Iterate over signatures
                for s in signatures:

                    # Iterate over offsets
                    for o in s.offsets:
                        address = pageaddress + o + cfg.PAGESIZE * j
                        r.append((address, s.length))
                        p.append(s)
                        count += 1

                        # If we have built a full vector, read from memory and
                        # compare to the corresponding signatures
                        if count == cfg.vectorsize:
                            # Read data from device
                            m = 0
                            for caddr, cand in self.interface.readv(r):
                                if self.match(cand, p[m].chunks):
                                    result = (caddr, p[m], o)
                                    # TODO: Log this in verbose mode?
                                    z.append(result)
                                    # If we have found the tagged signature,
                                    # or if we're only searching for the first
                                    # hit, return the vector or tuple,
                                    # respectively
                                    if findtag and p[m].tag:
                                        print()  # Filler
                                        return z
                                    elif not (findall or findtag):
                                        print()  # Filler
                                        return result
                                # Increment match vector counter
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
                             
                j += 1  # Increase read request count
        
        # Catch eventual exceptions, print a newline and pass them on
        except:
            print()  # Next line
            raise
        
        # If we end up here, return all found sigs, or raise an exception if
        # we're searching for just one (getting here means we didn't find it)
        print()  # Next line
        if (findtag or findall) and z:
            return z
        else:
            raise InceptionException('Could not locate signature(s)')
