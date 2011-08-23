'''
Created on Jun 19, 2011

@author: carmaa
'''

def print_msg(sign, message):
    print('[' + sign + '] ' + message)
        
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

        