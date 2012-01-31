'''
Created on Jun 19, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
import sys
import binascii
from inception import settings
import os

def msg(sign, message):
    # TODO: Add fancy print method that formats everything to 80 char wide string
    print('[' + str(sign) + '] ' + str(message))
        
    
def clean_hex(s):
    if isinstance(s, str) and s.startswith('0x'):
        s = s.replace('0x', '') # Remove '0x' strings from hex string
        if len(s) % 2 == 1: s = '0' + s # Pad with zero if odd-length string
        return binascii.unhexlify(bytes(s, sys.getdefaultencoding()))
    else:
        raise BytesWarning('Not a string starting with \'0x\'.')
    

def dirty_hex(b):
    if isinstance(b, bytes):
        return '0x' + bytes.decode(binascii.hexlify(b))
    else:
        raise BytesWarning('Not a byte string.')
        

def all_equal(iterator):
    try:
        iterator = iter(iterator)
        first = next(iterator)
        return all(first == rest for rest in iterator)
    except StopIteration:
        return True

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
    
    
def select(text, options):
    return input(text + '[' + str(o) +']:' for o in options)

def fail(err = None):
    '''
    Called if Inception fails. Optional parameter is an error message string.
    '''
    if err: msg('!', err)
    print('[!] Attack unsuccessful.')
    sys.exit(1)
    
def needtoavoid(address):
    return settings.avoid[0] <= address <= settings.avoid[1] and not settings.filemode and settings.override
        
class Context(object):
    '''
    classdocs
    '''
    # Constants
    PAGESIZE = 4096
    
    # Global variables/defaults
    verbose = False         # Not verbose
    fw_delay = 15           # 15 sec delay before attacking
    file_mode = False       # Search in file instead of FW DMA
    dry_run = False         # No write-back into memory
    target = False          # No target set
    file_name = ''          # No filename set
    buflen = 15             # Buffer length for checking if we get data
    memsize = 4294967296    # 4GB

    def __init__(self):
        '''
        Constructor
        '''
        
    def set_verbose(self, verbose):
        self.verbose = verbose 
    
    def set_encoding(self, encoding):
        self.encoding = encoding
    
    def set_config(self, config):
        self.config = config
    
    def set_fw_delay(self, fw_delay):
        self.fw_delay = fw_delay

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
        msg('!', 'Write to file not supported at the moment.')
        pass
    
    def close(self):
        pass

        