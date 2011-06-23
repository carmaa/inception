'''
Created on Jun 10, 2011

@author: carmaa
'''
#!/usr/bin/env python3.2
import getopt
import sys
import configparser
from ftwautopwn import unlock
from ftwautopwn.context import Context


def usage():
    print('''Usage: ftwautopwn [OPTIONS] -t target

Supply an URL to grab the web server's 'Server' HTTP Header.

    -h, --help:           Displays this message
    -l, --list:           Lists available target operating systems
    -s, --signatures=SIGNATURE_FILE:
                          Provide your own XML signature file
    -t TARGET, --target=TARGET:
                          Specify target operating system
    -v/--verbose:         Verbose mode''')


def main(argv):
    ctx = Context()
    encoding = sys.getdefaultencoding()
    ctx.set_encoding(encoding)
    config = configparser.ConfigParser()
    config.read('config.cfg')
    ctx.set_config(config)
    
    # Print header
    print('Fire Through the Wire Autopwn v.0.0.1')
    print('by Carsten Maartmann-Moe 2011\n')
    
    try:
        opts, args = getopt.getopt(argv, 'hvt:d:', ['help', 'verbose', \
                                                    'target=', 'delay='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-v', '--verbose'):
            ctx.set_verbose(True)
        elif opt in ('-t', '--target'):
            target = int(arg)
        elif opt in ('-d', '--delay'):
            global fw_delay
            fw_delay = int(arg)
        else:
            assert False, 'Unhandled option: ' + opt
    
    unlock.run(ctx)
        

if __name__ == '__main__':
    main(sys.argv[1:])
