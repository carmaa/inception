'''
Created on Jun 19, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
import sys
import binascii
from inception import settings
import os
import platform
from subprocess import call

def msg(sign, message):
    # TODO: Add fancy print method that formats everything to 80 char wide string
    print('[' + str(sign) + '] ' + str(message))
        
    
def clean_hex(s):
    '''
    Takes a string of hexadecimal characters preceded by '0x' and returns the
    corresponding byte string. That is, '0x41' becomes b'A'
    '''
    if isinstance(s, str) and s.startswith('0x'):
        s = s.replace('0x', '') # Remove '0x' strings from hex string
        if len(s) % 2 == 1: s = '0' + s # Pad with zero if odd-length string
        return binascii.unhexlify(bytes(s, sys.getdefaultencoding()))
    else:
        raise BytesWarning('Not a string starting with \'0x\'')
    

def dirty_hex(b):
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
    Converts an integer to its binary hexadecimal representation
    '''
    return clean_hex(hex(i))

def open_file(filename, mode):
    '''
    Opens a file that are a part of the package. The file must be in the folder
    tree beneath the main package
    '''
    this_dir, this_filename = os.path.split(__file__) #@UnusedVariable
    path = os.path.join(this_dir, filename)
    return open(path, mode)
    
    
def separator():
    '''
    Prints a separator line
    '''
    print('-' * 80)


def fail(err = None):
    '''
    Called if Inception fails. Optional parameter is an error message string.
    '''
    if err: msg('!', err)
    print('[!] Attack unsuccessful')
    sys.exit(1)


def needtoavoid(address):
    '''
    Checks if the address given as parameter is within the memory regions that
    the tool should avoid to make sure no kernel panics are induced at the
    target
    '''
    if settings.override:
        return False
    avoid = []
    if settings.apple:
        avoid = settings.apple_avoid # Avoid this region if dumping memory from Macs
    else:
        avoid = settings.avoid # Avoid this region if dumping memory from PCs
    return avoid[0] <= address <= avoid[1] and not settings.filemode


def detectos():
    '''
    Detects host operating system
    '''
    return platform.system()

def unloadIOFireWireIP():
    '''
    Unloads IP over FireWire modules if present on OS X
    '''
    unload = input('[!] IOFireWireIP on OS X may cause kernel panics. Unload? [Y/n]: ').lower()
    if 'y' == unload or '' == unload:
        status = call('kextunload /System/Library/Extensions/IOFireWireIP.kext', shell=True)
        if status == 0:
            msg('*', 'IOFireWireIP.kext unloaded')
            msg('*', 'To reload: sudo kextload /System/Library/Extensions/IOFireWireIP.kext')
        else:
            fail('Could not unload IOFireWireIP.kext')

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
    classdocs
    '''

    def __init__(self, file_name, pagesize):
        '''
        Constructor
        '''
        self.file = open(file_name, mode='rb')
        self.pagesize = pagesize
    
    def read(self, addr, numb, buf=None):
        self.file.seek(addr)
        return self.file.read(numb)  
    
    def readv(self, req):
        for r in req:
            self.file.seek(r[0])
            yield (r[0], self.file.read(r[1]))
    
    def write(self, addr, buf):
        '''
        For now, dummy method in order to simulate a write
        '''
        msg('!', 'Write to file not supported at the moment')
        pass
    
    def close(self):
        pass

        