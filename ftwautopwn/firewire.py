'''
Created on Jan 23, 2012

@author: carsten
'''
import re
from ftwautopwn.settings import OUICONF
from ftwautopwn.util import msg, separator
from ftwautopwn import settings

OUI = {}

def resolv_oui(vendor):
    try:
        return OUI[vendor]
    except KeyError:
        return ''

def init_OUI(filename = OUICONF):
    '''Populates the global OUI dictionary with mappings between 24 bit vendor
    identifier and a text string. Called during initialization. 

    Defaults to reading the value of module variable OUICONF.
    The file should have records like
    08-00-8D   (hex)                XYVISION INC.

    Feed it the standard IEEE public OUI file from
    http://standards.ieee.org/regauth/oui/oui.txt for a more up to date listing.
    '''
    try:
        f = open(filename, 'r')
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


def businfo(b):
    '''
    Prints all available information of the devices connected to the FireWire
    bus and looks up missing vendor names
    '''
    msg('*', 'FireWire devices on the bus (names may appear blank if not present):')
    separator()
    for number, device in enumerate(b.devices(), 1):
        vid = device.vendor_id
        vendorname = device.vendor_name.decode(settings.encoding)
        if not vendorname: vendorname = resolv_oui(vid) # Resolve not found name
        pid = device.product_id
        productname = device.product_name.decode(settings.encoding)
        msg(number, 'Vendor (ID): {0} ({1:#x}) | Product (ID): {2} ({3:#x})'.format(vendorname, vid, productname, pid))
    separator()