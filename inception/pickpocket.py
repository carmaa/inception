'''
Created on Feb 1, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''

from inception import firewire, memdump, settings
from inception.util import msg
import time
import sys

def lurk():
    print('[*] Lurking in the shrubbery waiting for a device to connect', end = '')
    sys.stdout.flush()
    try:
        fw = firewire.FireWire()
        while True: # Loop until aborted
            while len(fw.devices) == 0:
                print('.', end = '')
                sys.stdout.flush()
                time.sleep(settings.polldelay)
                pass # Do nothing until a device connects
            print() # Newline
            memdump.dump()
    except KeyboardInterrupt:
        msg('*', 'Interrupted.')  
