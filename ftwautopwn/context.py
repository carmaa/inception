'''
Created on Jun 23, 2011

@author: carmaa
'''

class Context(object):
    '''
    classdocs
    '''
    # Constants
    PAGESIZE = 4096
    
    # Global variables
    verbose = False
    fw_delay = 30

    def __init__(self):
        '''
        Constructor
        '''
        
    def set_verbose(self, verbose):
        self.verbose = verbose
        
    def get_verbose(self):
        return self.verbose
    
    def set_encoding(self, encoding):
        self.encoding = encoding
        
    def get_encoding(self):
        return self.encoding
    
    def set_config(self, config):
        self.config = config
    
    def get_config(self):
        return self.config
    
    def set_fw_delay(self, fw_delay):
        self.fw_delay = fw_delay
    
    def get_fw_delay(self):
        return self.fw_delay
        
        