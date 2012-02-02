'''
Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from binascii import hexlify
from inception import settings
from inception.firewire import FireWire
from inception.util import msg, MemoryFile, needtoavoid
import sys
import time
import os

def dump():
    # Initialize and lower DMA shield
    if not settings.filemode:
        fw = FireWire()
        starttime = time.time()
        device_index = fw.select_device()
        # Print selection
        msg('*', 'Selected device: ' + fw.vendors[device_index])#b = Bus()

    # Lower DMA shield or use a file as input
    device = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
    else:
        elapsed = int(time.time() - starttime)
        device = fw.getdevice(device_index, elapsed)
    
    start = settings.dumpstart    
    if settings.dumpsize: 
        size = settings.dumpsize
    else:
        if settings.filemode:
            size = os.path.getsize(settings.filename)
        else:
            size = settings.memsize
    
    end = start + size
    requestsize = settings.max_request_size

    filename = 'memdump_' + hex(start) + '-' + hex(end) + '.bin'
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
            dumped = (i - start) // settings.MiB
            sys.stdout.write('[*] Dumping memory, {0:>4d} MiB so far'.format(dumped))
            if settings.verbose:
                sys.stdout.write(' Sample data read: 0x' + hexlify(data[0:8]).decode(settings.encoding))
            sys.stdout.write('\r')
            sys.stdout.flush()
        file.close()
        print()
        msg('*', 'Dumped memory to file ' + filename)
        device.close()
    except KeyboardInterrupt:
        file.close()
        print()
        msg('*', 'Dumped memory to file ' + filename)
        raise KeyboardInterrupt