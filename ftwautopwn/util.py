'''
Created on Jun 19, 2011

@author: carmaa
'''
import sys
import binascii

def print_msg(sign, message):
    print('[' + sign + '] ' + message)
    
def clean_hex(s):
    s = s.replace('0x', '') # Remove '0x' strings from hex
    if len(s) % 2 == 1: s = '0' + s # Pad with zero if odd-length string
    return binascii.unhexlify(bytes(s, sys.getdefaultencoding()))

def all_equal(iterator):
    try:
        iterator = iter(iterator)
        first = next(iterator)
        return all(first == rest for rest in iterator)
    except StopIteration:
        return True
        
class Context(object):
    '''
    classdocs
    '''
    # Constants
    PAGESIZE = 4096
    
    # Global variables
    verbose = False
    fw_delay = 30
    file_mode = False
    dry_run = False
    target = False
    file_name = ''
    buflen = 15

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

        