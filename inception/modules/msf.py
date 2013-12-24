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

Created on Dec 5, 2013

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import firewire, cfg

info = '''A description of the module goes here.'''

def run():
    print('Running')

    # Start msf and generate shellcode(s) (in a separate thread?)

    # Search for signature

    # Figure out what os & architecture we're attacking and select stage

    # Copy off original memory content in the region where stage 1 will be written

    # Patch with stage 1 - allocates a memory page and writes signature to frame boundary, and jumps to it

    # Search for signature

    # Restore the original memory content where stage 1 was written (overwrite it)

    # Patch with stage 2 - forks / creates and executes a new thread with prepended shellcode


def usage():
    pass