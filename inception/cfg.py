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

Created on Sep 6, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from textwrap import TextWrapper


#==============================================================================
# General information
#==============================================================================
version = '0.3.4'
url = 'http://breaknenter.org/projects/inception'

#==============================================================================
# Global objects
#==============================================================================
wrapper = TextWrapper(subsequent_indent=' ' * 4)

#==============================================================================
# Constants
#==============================================================================
DEBUG = 0                           # Debug off
KiB = 1024                          # One KibiByte
MiB = 1024 * KiB                    # One MebiByte
GiB = 1024 * MiB                    # One GibiByte
PAGESIZE = 4 * KiB                  # In this tool, always the case
OUICONF = 'resources/oui.txt'       # FireWire OUI database relative to package
LINUX = 'Linux'
OSX = 'Darwin'
WINDOWS = 'Windows'
    
#==============================================================================
# Environment variables
#==============================================================================
buflen = 15                     # Buffer length for checking if we get data
memsize = 4 * GiB               # 4 GiB, theoretical FW max
success = True                  # Optimistic-by-nature setting
encoding = None                 # System encoding
vectorsize = 128                # Read vector size
max_request_size = PAGESIZE//2  # By default the max request size is the PSZ/2
avoid = False                   # Do we need to avoid certain regions of memory
pc_avoid = [0xa0000, 0xfffff]   # Memory area that can cause BSOD if accessed)
apple_avoid = [0x0, 0xff000]    # Avoid this area if dumping memory from Macs
apple_target = False            # Set to true if we are attacking a Mac
polldelay = 1                   # 1 second delay between FireWire polls
os = None                       # Detected host OS is None by default

#==============================================================================
# Options (i.e. these are the defaults, but may be overridden at invocation)
#==============================================================================
delay = 5                       # 5 seconds delay before attacking
target = False                  # No target set
memdump = False                 # Memory dump mode off
startaddress = 0                # Default memory start address
dumpsize = False                # Not set by default
interactive = False             # Interactive mode off
pickpocket = False              # Pickpocket mode off by default
patchfile = ''                  # Read patch from file
revert = False                  # Revert the patch after we are done
forcewrite = False              # Do not write back to file in file mode
list_signatures = False         # Don't list all signatures at startup

#==============================================================================
# Easter
#==============================================================================
egg = False
eggs = []
