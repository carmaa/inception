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

Created on Jan 22, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''

import time

from inception import cfg, util, terminal
from inception.exceptions import InceptionException


IS_INTRUSIVE = False

term = terminal.Terminal()

info = 'Dumps memory content to a file.'

filename_prefix = 'memdump'  # Prefix for memory dump file
filename_ext = 'bin'         # Binary extesnion for memory dumps
filename = ''


def add_options(parser):
    parser.add_option('-a', '--address',
                      dest='address',
                      help='start address for dump. Can be given as an '
                           'integer, a hexadecimal string prefixed with '
                           '\'0x\', or as a page number prefixed with p. Note '
                           'that due to unreliable behavior on some targets '
                           'when accessing data below 1 MiB, this command '
                           'will avoid that region of upper memory when '
                           'dumping, and replace the first MB with zeroes.')
    parser.add_option('-s', '--size',
                      dest='size',
                      help='the size (expressed in pages or memory size) to '
                           'dump. The size can be anumber of pages or a size '
                           'of data using the denomination KiB, MiB GiB. '
                           'Example: If you give the arguments "-s 5MiB", '
                           'tool dumps the 5 MiB of memory. Another example: '
                           '"-s 5 will dump 5 bytes.')
    parser.add_option('-p', '--prefix',
                      dest='prefix',
                      help='specify the file name prefix of the dump file.')


def calculate(address, size):
    '''Calculate the start and end memory addresses of the dump'''
    try:
        # Fix address
        if isinstance(address, int):
            pass
        elif address.startswith('0x'):
            address = int(address, 0) & 0xfffff000  # Address
        elif address.startswith('p'):
            address = int(address[1:]) * cfg.PAGESIZE  # Page number
        else:
            address = int(address)  # Integer

        # Fix size
        try:
            size = util.parse_unit(size)
        except ValueError as e:
            raise InceptionException('Could not parse "{0}" to a valid data '
                                     'size: {1}'.format(size, e))
        if size < cfg.PAGESIZE:
            term.warn('Minimum dump size is a page, {0} KiB'
                      .format(cfg.PAGESIZE // cfg.KiB))
        end = address + size
        return address, end
    except Exception as e:
        raise InceptionException('Could not calculate start and end memory '
                                 'address', e)


def run(opts, memspace):
    # Ensure that the filename is accessible outside this module
    global filename

    # Set start and end parameters based on user input. If no input is given,
    # start at zero (i.e., the beginning of main memory)
    end = memspace.memsize
    if opts.address and opts.size:
        start, end = calculate(opts.address, opts.size)
    elif opts.address:
        raise InceptionException('Missing parameter "size"')
    elif opts.size:
        raise InceptionException('Missing parameter "address"')
    else:
        start = 0  # May be overridden later

    # Make sure that the right mode is set
    # cfg.memdump = True #TODO: do we really need this?
    
    # Ensure correct denomination
    size = end - start
    if size % cfg.GiB == 0:
        s = '{0} GiB'.format(size // cfg.GiB)
    elif size % cfg.MiB == 0:
        s = '{0} MiB'.format(size // cfg.MiB)
    else:
        s = '{0} KiB'.format(size // cfg.KiB)
    
    if opts.prefix:
        prefix = opts.prefix
    else:
        prefix = filename_prefix

    # Open file for writing
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = '{0}_{1}-{2}_{3}.{4}'.format(prefix,
                                            hex(start), hex(end),
                                            timestr,
                                            filename_ext)
    term.info('Dumping from {0:#x} to {1:#x}, a total of {2}:'
              .format(start, end, s))
    file = open(filename, 'wb')

    # Progress bar
    prog = term.ProgressBar(min_value=start, max_value=end,
                            total_width=term.wrapper.width)

    if size < cfg.max_request_size:
        requestsize = size
    else:
        requestsize = cfg.max_request_size
    try:
        for i in range(start, end, requestsize):
            # Edge case, make sure that we don't read beyond the end
            if i + requestsize > end:
                requestsize = end - i
            data = memspace.read(i, requestsize)
            file.write(data)
            # Print status
            prog.update_amount(i + requestsize, data)
            prog.draw()
        file.close()
        print()  # Filler
        term.info('Dumped memory to file {0}'.format(filename))
        # device.close()
    except KeyboardInterrupt:
        file.close()
        print()  # Filler
        # device.close()
        term.info('Partial memory dumped to file {0}'.format(filename))
        raise KeyboardInterrupt
