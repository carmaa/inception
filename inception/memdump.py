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

Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''

from inception import cfg, firewire, util
import time

filename = ''

def dump(start, end):
    # Ensure that the filename is accessible outside this module
    global filename

    # Make sure that the right mode is set
    cfg.memdump = True
    
    requestsize = cfg.max_request_size
    size = end - start
    
    # Open file for writing
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = '{0}_{1}-{2}_{3}.{4}'.format(cfg.memdump_prefix, 
                                            hex(start), hex(end),
                                            timestr,
                                            cfg.memdump_ext)
    file = open(filename, 'wb')
    
    # Ensure correct denomination
    if size % cfg.GiB == 0:
        s = '{0} GiB'.format(size//cfg.GiB)
    elif size % cfg.MiB == 0:
        s = '{0} MiB'.format(size//cfg.MiB)
    else:
        s = '{0} KiB'.format(size//cfg.KiB)
        
    term.info('Dumping from {0:#x} to {1:#x}, a total of {2}'
              .format(start, end, s))
    
    # Initialize and lower DMA shield
    if not cfg.filemode:
        fw = firewire.FireWire()
        starttime = time.time()
        device_index = fw.select_device()
        # Print selection
        term.info('Selected device: {0}'.format(fw.vendors[device_index]))

    # Lower DMA shield or use a file as input
    device = None
    if cfg.filemode:
        device = util.MemoryFile(opts.filename, cfg.PAGESIZE)
    else:
        elapsed = int(time.time() - starttime)
        device = fw.getdevice(device_index, elapsed)

    # Progress bar
    prog = term.ProgressBar(min_value = start, max_value = end, 
                            total_width = wrapper.width, 
                            print_data = opts.verbose)


    try:
        # Fill the first MB and avoid reading from that region
        if not cfg.filemode:
            fillsize = cfg.startaddress - start
            data = b'\x00' * fillsize
            file.write(data)
            start = cfg.startaddress
        for i in range(start, end, requestsize):
            # Edge case, make sure that we don't read beyond the end
            if  i + requestsize > end:
                requestsize = end - i
            data = device.read(i, requestsize)
            file.write(data)
            # Print status
            prog.update_amount(i + requestsize, data)
            prog.draw()
        file.close()
        print() # Filler
        term.info('Dumped memory to file {0}'.format(filename))
        device.close()
    except KeyboardInterrupt:
        file.close()
        print()
        term.info('Dumped memory to file {0}'.format(filename))
        raise KeyboardInterrupt
