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

Created on Jun 19, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from inception import cfg, term
from subprocess import call
import binascii
import os
import platform
import sys


def hexstr2bytes(s):
    '''
    Takes a string of hexadecimal characters preceded by '0x' and returns the
    corresponding byte string. That is, '0x41' becomes b'A'
    '''
    if isinstance(s, str) and s.startswith('0x'):
        s = s.replace('0x', '') # Remove '0x' strings from hex string
        if len(s) % 2 == 1: s = '0' + s # Pad with zero if odd-length string
        return binascii.unhexlify(bytes(s, sys.getdefaultencoding()))
    else:
        raise BytesWarning('Not a string starting with \'0x\': {0}'.format(s))
    

def bytes2hexstr(b):
    '''
    Takes a string of bytes and returns a string with the corresponding
    hexadecimal representation. Example: b'A' becomes '0x41'
    '''
    if isinstance(b, bytes):
        return '0x' + bytes.decode(binascii.hexlify(b))
    else:
        raise BytesWarning('Not a byte string')
        

def bytelen(s):
    '''
    Returns the byte length of an integer
    '''
    return (len(hex(s))) // 2


def int2binhex(i):
    '''
    Converts positive integer to its binary hexadecimal representation
    '''
    if i < 0:
        raise TypeError('Not a positive integer: {0}'.format(i))
    return hexstr2bytes(hex(i))


def open_file(filename, mode):
    '''
    Opens a file that are a part of the package. The file must be in the folder
    tree beneath the main package
    '''
    this_dir, this_filename = os.path.split(__file__) #@UnusedVariable
    path = os.path.join(this_dir, filename)
    return open(path, mode)
    

def parse_unit(size):
    '''
    Parses input in the form of a number and a (optional) unit and returns the
    size in either multiplies of the page size (if no unit is given) or the
    size in KiB, MiB or GiB
    '''
    size = size.lower()
    if size.find('kib') != -1 or size.find('kb') != -1:
        size = int(size.rstrip(' kib')) * cfg.KiB
    elif size.find('mib') != -1 or size.find('mb') != -1:
        size = int(size.rstrip(' mib')) * cfg.MiB
    elif size.find('gib') != -1 or size.find('gb') != -1:
        size = int(size.rstrip(' gib')) * cfg.GiB
    else:
        size = int(size) * cfg.PAGESIZE
    return size


def needtoavoid(address):
    '''
    Checks if the address given as parameter is within the memory regions that
    the tool should avoid to make sure no kernel panics are induced at the
    target
    '''
    avoid = []
    if cfg.apple_target:
        avoid = cfg.apple_avoid # Avoid this region if dumping from Macs
    else:
        avoid = cfg.avoid # Avoid this region if dumping memory from PCs
    return avoid[0] <= address <= avoid[1] and not cfg.filemode


def detectos():
    '''
    Detects host operating system
    '''
    return platform.system()


def unload_fw_ip():
    '''
    Unloads IP over FireWire modules if present on OS X
    '''
    term.poll('IOFireWireIP on OS X may cause kernel panics. Unload? [Y/n]: ')
    unload = input().lower()
    if unload in ['y', '']:
        status = call('kextunload /System/Library/Extensions/IOFireWireIP.kext',
                      shell=True)
        if status == 0:
            term.info('IOFireWireIP.kext unloaded')
            term.info('To reload: sudo kextload /System/Library/Extensions/' +
                 'IOFireWireIP.kext')
        else:
            term.fail('Could not unload IOFireWireIP.kext')


def restart():
    '''
    Restarts the current program.
    Note: this function does not return. Any cleanup action (like
    saving data) must be done before calling this function.
    '''
    python = sys.executable
    os.execl(python, python, * sys.argv)


class MemoryFile:
    '''
    File that exposes a similar interface as the FireWire class. Used for
    reading from RAM memory files of memory dumps
    '''

    def __init__(self, file_name, pagesize):
        '''
        Constructor
        '''
        self.file = open(file_name, mode='r+b')
        self.pagesize = pagesize
    
    def read(self, addr, numb, buf=None):
        self.file.seek(addr)
        return self.file.read(numb)  
    
    def readv(self, req):
        for r in req:
            self.file.seek(r[0])
            yield (r[0], self.file.read(r[1]))
    
    def write(self, addr, buf):
        if cfg.forcewrite:
            term.poll('Are you sure you want to write to file [y/N]? ')
            answer = input().lower()
            if answer in ['y', 'yes']:
                self.file.seek(addr)
                self.file.write(buf)
        else:
            term.warn('File not patched. To enable file writing, use the ' +
                 '--force-write switch')
    
    def close(self):
        self.file.close()
    
    

