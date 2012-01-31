'''
Created on Jan 23, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
import re
from inception.util import msg, separator, fail, open_file
from inception import settings
import sys
import time
from forensic1394.bus import Bus
import os

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
        
        # Enable SBP-2 support to ensure we get DMA
        self._bus.enable_sbp2()
        self._devices = self._bus.devices()
        self._oui = self.init_OUI()
        self._vendors = []
        self._max_request_size = settings.PAGESIZE
        
    def init_OUI(self, filename = settings.OUICONF):
        '''Populates the global OUI dictionary with mappings between 24 bit vendor
        identifier and a text string. Called during initialization. 
    
        Defaults to reading the value of module variable OUICONF.
        The file should have records like
        08-00-8D   (hex)                XYVISION INC.
    
        Feed it the standard IEEE public OUI file from
        http://standards.ieee.org/regauth/oui/oui.txt for a more up to date listing.
        '''
        OUI = {}
        try:
            f = open_file(filename, 'r')
            lines = f.readlines()
            f.close()
            regex = re.compile('(?P<id>([0-9a-fA-F]{2}-){2}[0-9a-fA-F]{2})\s+\(hex\)\s+(?P<name>.*)')
            for l in lines:
                rm = regex.match(l)
                if rm != None:
                    textid = rm.groupdict()['id']
                    ouiid = int('0x%s%s%s' % (textid[0:2], textid[3:5], textid[6:8]), 16)
                    OUI[ouiid] = rm.groupdict()['name']
        except IOError:
            msg('!', 'Vendor OUI lookups will not be performed: {0}'.format(filename))
        return OUI
            
    def resolve_oui(self, vendor):
        try:
            return self._oui[vendor]
        except KeyError:
            return ''
            
    def businfo(self):
        '''
        Prints all available information of the devices connected to the FireWire
        bus and looks up missing vendor names & populates the internal vendor
        list. Must be called before attempting to autodetect type of operating 
        system connected to the bus
        '''
        if not self._devices:
            fail('No FireWire devices detected on the bus')
        msg('*', 'FireWire devices on the bus (names may appear blank):')
        separator()
        for n, device in enumerate(self._devices, 1):
            vid = device.vendor_id
            vendorname = device.vendor_name.decode(settings.encoding)
            if not vendorname: vendorname = self.resolve_oui(vid) # Resolve not found name
            self._vendors.append(vendorname)
            pid = device.product_id
            productname = device.product_name.decode(settings.encoding)
            msg(n, 'Vendor (ID): {0} ({1:#x}) | Product (ID): {2} ({3:#x})'.format(vendorname, 
                                                                                   vid, productname, pid))
        separator()
    
    def select_device(self):
        if not self._vendors:
            self.businfo()
        nof_devices = len(self._vendors)
        if nof_devices == 1:
            msg('*', 'Only one device present, device auto-selected as target')
            selected = 0
        else:
            selected = input('Please select a device to attack (or enter \'q\' to quit): ')
            try:
                selected = int(selected)
            except:
                if selected == 'q': sys.exit()
                else:
                    msg('!', 'Invalid selection, please try again. Type \'q\' to quit')
                    return self.select_device()
        if selected <= nof_devices:
            i = selected - 1 
#            vendor = self._vendors[i]
#            if 'apple' in vendor.lower():
#                msg('*', 'The target machine seems to be a Mac, forcing max request size to 2 KiB')
#                settings.max_request_size = 2 * settings.KiB
            return i
        else:
            msg('!', 'Please enter a selection between 1 and ' + str(nof_devices) + '. Type \'q\' to quit')
            return self.select_device()
    
    def detect_targets(self, targets, vendor_index):
        #vendors = self.businfo()
        pass
        
    def getdevice(self, num, elapsed):
        try:
            for i in range(settings.fw_delay - elapsed, 0, -1):
                sys.stdout.write('[*] Initializing bus and enabling SBP-2, please wait %2d seconds or press Ctrl+C\r' % i)
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        d = self._bus.devices()[num]
        d.open()
        print() # Create a newline so that next call to print() will start on a new line
        return d
            
    @property
    def bus(self):
        """
        The firewire bus; Bus.
        """
        return self._bus
    
    @property
    def devices(self):
        """
        The firewire devices connected to the bus; list of Device.
        """
        return self._devices
    
    @property
    def oui(self):
        """
        The OUI dict
        """
        return self._oui
    
    @property
    def vendors(self):
        """
        The list of vendors
        """
        return self._vendors
