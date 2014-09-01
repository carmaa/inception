#!/usr/bin/env python3
import binascii
import sys

if __name__ == '__main__':
    arg = sys.argv[1]
    print("b'{}'".format(''.join('\\x{:02x}'.format(b) for b in binascii.unhexlify(arg.replace('0x', '')))))