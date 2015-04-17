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

This module provides the ability to use inception using SLOTSCREAMER.
Most of the code is adopted from the slotscreamer samples with slight
modification.

Created on Jan 16th, 2015

@author: Inception Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy

The SLOTSCREAMER project is part of the NSA-Playset and is available at:

https://github.com/NSAPlayset/SLOTSCREAMER

SLOTSCREAMER initial authors: Joe Fitz - joefitz@securinghardware.com and
Miles Crabilll - miles@milescrabill.com
'''

from inception import cfg, terminal
from inception.exceptions import InceptionException

import usb.core
import usb.util
import struct


term = terminal.Terminal()


def initialize(opts, module):
    # Convenience function to initialize the interface.

    # Mandatory arguments:

    # Lower DMA shield, and set memsize
    device = SlotScreamer()
    memsize = cfg.memsize
    return device, memsize


class SlotScreamer:
    # Interface to the SlotScreamer native PCIe device over USB with pyusb

    def __init__(self):
        
        # find our device
        try:
            dev = usb.core.find(idVendor=0x0525, idProduct=0x3380)
        except ValueError:
            raise InceptionException('SLOTSCREAMER device not found')
        dev.set_configuration()
        cfg = dev.get_active_configuration()
        intf = cfg[0, 0]

        self.pciin = usb.util.find_descriptor(intf, custom_match=lambda e:
                                              e.bEndpointAddress == 0x8e)
        assert self.pciin is not None, 'SLOTSCREAMER pciin endpoint not found'
        term.info('SLOTSCREAMER PCIIN found: ' + str(self.pciin) + '\n')
        
        self.pciout = usb.util.find_descriptor(intf, custom_match=lambda e:
                                               e.bEndpointAddress == 0xe)
        assert self.pciout is not None, 'pciout endpoint not found'
        term.info('SLOTSCREAMER PCIOUT found: ' + str(self.pciout) + '\n')
        self.cache = []
    
    def read(self, addr, numb, buf=None):
        try:
            # round down to multiple of 256
            offset = addr % 256
            base_addr = addr - offset
            end_offset = (addr + numb) % 256
            end_addr = addr + numb - offset + 256
            # cache most recent read
            # check if anything is cached
            if (len(self.cache) > 0):
                if((self.cacheBase <= addr) and
                   ((self.cacheBase + len(self.cache)) > (addr + numb))):
                    return bytes(self.cache[(addr - self.cacheBase):
                                            (addr + numb) - self.cacheBase])
            self.cache = []
            self.cacheBase = base_addr
            while base_addr < end_addr:
                self.pciout.write(struct.pack('BBBBI', 0xcf, 0, 0, 0x40,
                                              base_addr))
                self.cache += self.pciin.read(0x100)
                base_addr += 256
        except IOError:
            self.cache = []
            return bytes(b"bad" + b"\x10") * 64
        return bytes(self.cache[offset:offset + numb])

    def readv(self, req):
        # sort requests so sequential reads are cached
        # req.sort()
        for r in req:
            yield(r[0], self.read(r[0], r[1]))

    def write(self, addr, buf):
        offset = addr % 256
        base_addr = addr - offset
        byte_count = len(buf)
        end_offset = (addr + byte_count) % 256
        end_addr = addr + byte_count - end_offset + 256

        # readbuffer
        readbuf = bytearray(self.read(base_addr, end_addr - base_addr))

        # modify buffer
        for i in range(offset, end_offset):
            readbuf[i] = buf[i - offset]

        # writebuffer
        buffer_index = 0
        while base_addr < end_addr:
            subbuf = readbuf[buffer_index:buffer_index + 128]
            self.pciout.write(struct.pack('BBBBI' + 'B' * 128, 0x4f, 0, 0,
                                          0x20, base_addr, *subbuf))
            base_addr += 128
            buffer_index += 128

        global cache
        self.cache = []
       
    def close(self):
        self.cache = []
