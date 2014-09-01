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

Created on Jun 19, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import os
import platform
import sys

import binascii
from inception import cfg


class EscapeAll(bytes):
    def __str__(self):
        return ''.join('\\x{:02x}'.format(b) for b in self)


def hexstr2bytes(s):
    '''
    Takes a string of hexadecimal characters preceded by '0x' and returns the
    corresponding byte string. That is, '0x41' becomes b'A'
    '''
    if isinstance(s, str) and s.startswith('0x'):
        s = s.replace('0x', '')  # Remove '0x' strings from hex string
        if len(s) % 2 == 1:
            s = '0' + s  # Pad with zero if odd-length string
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


def str2bytes(s):
    '''
    Takes a string of the format '\x01\xff' and converts it to a bytes object.
    '''
    if isinstance(s, str):
        return s.encode('latin-1')
    else:
        raise TypeError('Not a string: {0}'.format(s))


def bytelen(s):
    '''
    Returns the byte length of an integer
    '''
    return (len(hex(s))) // 2


def int2bytes(i):
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
    this_dir, this_filename = os.path.split(__file__)  # @UnusedVariable
    path = os.path.join(this_dir, filename)
    return open(path, mode)
    

def parse_unit(size):
    '''
    Parses input in the form of a number and a (optional) unit and returns the
    size in either multiplies of the page size (if no unit is given) or the
    size in KiB, MiB or GiB
    '''
    if isinstance(size, int):
        return size
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


def detectos():
    '''
    Detects host operating system
    '''
    return platform.system()


def cleanup():
    '''
    Cleans up at exit
    '''
    if cfg.eggs:
        for egg in cfg.eggs:
            egg.terminate()


def restart():
    '''
    Restarts the current program. Note: this function does not return.
    '''
    python = sys.executable
    os.execl(python, python, * sys.argv)
