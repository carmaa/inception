#!/usr/bin/env python3

from optparse import OptionParser

import collections

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMetasploit Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'parseargs'
]

def convert(data):
    '''
    Converts data in the msgpack dicts from binary to strings (or other data types)
    '''
    if isinstance(data, bytes):
        try:
            return data.decode('ascii')
        except UnicodeDecodeError:
            return data
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.items()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data


def parseargs():
    p = OptionParser()
    p.add_option("-P", dest="password", help="Specify the password to access msfrpcd", metavar="opt")
    p.add_option("-S", dest="ssl", help="Disable SSL on the RPC socket", action="store_false", default=True)
    p.add_option("-U", dest="username", help="Specify the username to access msfrpcd", metavar="opt", default="msf")
    p.add_option("-a", dest="server", help="Connect to this IP address", metavar="host", default="127.0.0.1")
    p.add_option("-p", dest="port", help="Connect to the specified port instead of 55553", metavar="opt", default=55553)
    o, a = p.parse_args()
    if o.password is None:
        print('[-] Error: a password must be specified (-P)\n')
        p.print_help()
        exit(-1)
    return o