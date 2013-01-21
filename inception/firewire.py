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

Created on Jan 23, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
from inception import cfg, util, term
from subprocess import call
import os
import re
import sys
import time

# Error handling for cases where libforensic1394 is not installed in /usr/lib
try:
    from forensic1394.bus import Bus
except OSError:
    host_os = util.detectos()
    try:
        path = os.environ['LD_LIBRARY_PATH']
    except KeyError:
        path = ''
    # If the host OS is Linux, we may need to set LD_LIBRARY_PATH to make python
    # find the libs
    if host_os == cfg.LINUX and '/usr/local/lib' not in path:
        os.putenv('LD_LIBRARY_PATH', "/usr/local/lib")
        util.restart()
    else:
        term.fail('Could not load libforensic1394')

# List of FireWire OUIs
OUI = {}

class FireWire:
    '''
    FireWire wrapper class to handle some attack-specific functions
    '''

    def __init__(self):
        '''
        Constructor
        Initializes the bus and sets device, OUI variables
        '''
        self._bus = Bus()
        try:
            self._bus.enable_sbp2()
        except IOError:
            term.poll('FireWire modules are not loaded. Load them? [Y/n]: ')
            answer = input().lower()
            if answer in ['y', '']:
                status = call('modprobe firewire-ohci', shell=True)
                if status == 0:
                    try:
                        self._bus.enable_sbp2()
                    except IOError:
                        time.sleep(2) # Give some more time
                        self._bus.enable_sbp2() # If this fails, fail hard
                    term.info('FireWire modules loaded successfully')
                else:
                    term.fail('Could not load FireWire modules')
            else:
                term.fail('FireWire modules not loaded')
                
        # Enable SBP-2 support to ensure we get DMA
        self._devices = self._bus.devices()
        self._oui = self.init_OUI()
        self._vendors = []
        self._max_request_size = cfg.PAGESIZE
        
        
    def init_OUI(self, filename = cfg.OUICONF):
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
            regex = re.compile('(?P<id>([0-9a-fA-F]{2}-){2}[0-9a-fA-F]{2})' + 
                               '\s+\(hex\)\s+(?P<name>.*)')
            for l in lines:
                rm = regex.match(l)
                if rm != None:
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
            term.fail('No FireWire devices detected on the bus')
        term.info('FireWire devices on the bus (names may appear blank):')
        term.separator()
        for n, device in enumerate(self._devices, 1):
            vid = device.vendor_id
            # In the current version of libforensic1394, the 
            # device.vendor_name.decode() method cannot be trusted (it  ofen
            # returns erroneous data. We'll rely on OUI lookups instead
            # vendorname = device.vendor_name.decode(cfg.encoding)
            vendorname = self.resolve_oui(vid)
            self._vendors.append(vendorname)
            pid = device.product_id
            productname = device.product_name.decode(cfg.encoding)
            term.info('Vendor (ID): {0} ({1:#x}) | Product (ID): {2} ({3:#x})'
                      .format(vendorname, vid, productname, pid), sign = n)
        term.separator()
        
    
    def select_device(self):
        '''
        Present the user of the option to select what device (connected to the
        bus) to attack
        '''
        if not self._vendors:
            self.businfo()
        nof_devices = len(self._vendors)
        if nof_devices == 1:
            if cfg.verbose:
                term.info('Only one device present, device auto-selected as ' +
                          'target')
            return 0
        else:
            term.poll('Select a device to attack (or type \'q\' to quit): ')
            selected = input().lower()
            try:
                selected = int(selected)
            except:
                if selected == 'q': sys.exit()
                else:
                    term.warn('Invalid selection. Type \'q\' to quit')
                    return self.select_device()
        if 0 < selected <= nof_devices:
            i = selected - 1
            vendor = self._vendors[i]
            # If the target is a Mac, and we are in memdump mode with the
            # --override switch set, make sure we don't touch OS X's g-spot
            # (which would likely cause a kernel panic)
            if 'apple' in vendor.lower() and cfg.memdump and cfg.override:
                cfg.apple_target = True
                term.info('The target seems to be a Mac, forcing avoidance ' +
                          '(not dumping {0:#x}-{1:#x})'
                          .format(cfg.apple_avoid[0], cfg.apple_avoid[1]))
            return i
        else:
            term.warn('Enter a selection between 1 and ' + str(nof_devices) + 
                      '. Type \'q\' to quit')
            return self.select_device()
        
        
    def getdevice(self, num, elapsed):
        didwait = False
        bb = term.BeachBall()
        try:
            for i in range(cfg.fw_delay - elapsed, 0, -1):
                print('[*] Initializing bus and enabling SBP-2, ' +
                      'please wait %2d seconds or press Ctrl+C\r' 
                      % i, end = '')
                sys.stdout.flush()
                bb.draw()
                didwait = True
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        d = self._bus.devices()[num]
        d.open()
        if didwait: 
            print() # Create a LF so that next print() will start on a new line
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

