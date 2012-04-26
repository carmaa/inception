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

Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from binascii import hexlify
from inception import settings
from inception.firewire import FireWire
from inception.util import msg, MemoryFile, needtoavoid
import sys
import time

def dump(start, end):
    # Make sure that the right mode is set
    settings.memdump = True
    
    # Initialize and lower DMA shield
    if not settings.filemode:
        fw = FireWire()
        starttime = time.time()
        device_index = fw.select_device()
        # Print selection
        msg('*', 'Selected device: ' + fw.vendors[device_index])

    # Lower DMA shield or use a file as input
    device = None
    if settings.filemode:
        device = MemoryFile(settings.filename, settings.PAGESIZE)
    else:
        elapsed = int(time.time() - starttime)
        device = fw.getdevice(device_index, elapsed)
        
    requestsize = settings.max_request_size
    size = end - start

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
                sys.stdout.write('. Sample data read: 0x' + hexlify(data[0:8]).decode(settings.encoding))
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
