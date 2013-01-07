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

Created on Feb 1, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from inception import firewire, memdump, cfg
import time
from inception.util import BeachBall, info

def lurk():
    start = cfg.startaddress
    end = cfg.memsize
    bb = BeachBall()
    
    try:
        s = '\n'.join(cfg.wrapper.wrap('[-] Lurking in the shrubbery waiting ' +
                                       'for a device to connect. Ctrl-C to ' +
                                       'abort')) + '\r'
        print(s, end = '')
        # Initiate FireWire
        fw = firewire.FireWire()
        while True: # Loop until aborted, and poll for devices
            while len(fw.devices) == 0:
                bb.draw()
                time.sleep(cfg.polldelay)
                pass # Do nothing until a device connects
            print() # Newline
            info('FireWire device detected')
            memdump.dump(start, end)
    except KeyboardInterrupt:
        print() # TODO: Fix keyboard handling (interrupt handling)
        raise KeyboardInterrupt
        
