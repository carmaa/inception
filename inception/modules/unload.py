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

Created on Jun 29, 2014

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import cfg, util
from inception.interfaces import firewire

info = 'OS X only: Unloads IOFireWireIP.kext (OS X IP over FireWire module) which ' \
'are known to cause kernel panics when the host (attacking system) is OS X. ' \
'Must be executed BEFORE any FireWire devices are connected to the host.'

def add_options(parser):
    pass

def run(opts, memory):
    if cfg.os == cfg.OSX:
        firewire.unload_fw_ip()
    else:
        term.fail('Host system is not OS X, aborting')