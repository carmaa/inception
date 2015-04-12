'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
PCI-based and IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2014  Carsten Maartmann-Moe

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

Created on Jan 23, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import os

from inception import cfg, terminal
from inception.exceptions import InceptionException


term = terminal.Terminal()


def initialize(opts, module):
    '''
    Convenience function to initialize the interface.

    Mandatory arguments:
    - opts: the options that the program was initiated with
    '''
    # Check if a file name has been set
    if not opts.filename:
        raise InceptionException('You must specify a file name to utilize '
                                 'this interface.')

    # Check if the file exists
    if not os.path.isfile(opts.filename):
        raise InceptionException('No such file: \'{0}\''.format(opts.filename))

    # Warn user that using the interface may write to file
    try:  # TODO: Fix this more elegantly?
        dry_run = opts.dry_run
    except AttributeError:
        dry_run = False
    if module.IS_INTRUSIVE and not dry_run:
        answer = term.poll('Will potentially write to file. OK? [y/N]',
                           default='n')
        if answer in ['n']:
            dry_run = True

    # Lower DMA shield, and set memsize
    device = MemoryInterface(opts.filename, cfg.PAGESIZE, dry_run)
    memsize = os.path.getsize(opts.filename)
    return device, memsize


class MemoryInterface:
    '''
    File that exposes a similar interface as the FireWire Device class. Used
    for reading from RAM memory files of memory dumps
    '''

    def __init__(self, file_name, pagesize, dry_run):
        '''
        Constructor
        '''
        self.file = open(file_name, mode='r+b')
        self.pagesize = pagesize
        self.dry_run = dry_run
    
    def read(self, addr, numb, buf=None):
        self.file.seek(addr)
        return self.file.read(numb)
    
    def readv(self, req):
        for r in req:
            self.file.seek(r[0])
            yield (r[0], self.file.read(r[1]))
    
    def write(self, addr, buf):
        if not self.dry_run:
            self.file.seek(addr)
            self.file.write(buf)
    
    def close(self):
        self.file.close()
