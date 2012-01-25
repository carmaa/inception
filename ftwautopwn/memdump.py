'''
Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from forensic1394 import Bus 
from time import sleep
from ftwautopwn import settings
from ftwautopwn.util import msg, fail, MemoryFile, findmemsize
from ftwautopwn.firewire import FireWire
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
    
    print(start)
    print(size)
    print(end)
    print(requestsize)
    
    try:
        
        for i in range(start, int(size/requestsize)):
        # Skip the first MB
            file.write(device.read(settings.MiB + i * requestsize, requestsize))
        file.close()
        msg('*', 'Dumped memory to file ' + filename)
        device.close()
    except IOError as exc:
        print(exc)