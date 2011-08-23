'''
Created on Jun 10, 2011

@author: carmaa
'''
#!/usr/bin/env python3.2
from ftwautopwn import unlock
from ftwautopwn.util import Context
import configparser
import getopt
import sys

def usage():
    print('''Usage: ftwautopwn [OPTIONS]

Supply an URL to grab the web server's 'Server' HTTP Header.

    -d --delay=TIME:      Delay attack by TIME seconds. This is useful in order
                          to guarantee that the target machine has successfully
                          installed the SBP2 device before attacking. If the
                          attack fails, try to increase this value.
    -f --file=FILE:       Use a file instead of FireWire bus data as input; for
                          example to facilitate attacks on VMware machines or
                          to ease testing and signature generation efforts
    -h, --help:           Displays this message
    -l, --list:           Lists available target operating systems
    -n, --no-write:       Dry run, do not write back to memory
    -t TARGET, --target=TARGET:
                          Specify target operating system (use --list to list 
                          available targets)
    -v/--verbose:         Verbose mode''')


def main(argv):
    ctx = Context()
    encoding = sys.getdefaultencoding()
    ctx.set_encoding(encoding)
    config = configparser.ConfigParser()
    config.read('config.cfg')
    ctx.config = (config)
    
    # Print banner
    print('Fire Through the Wire Autopwn v.0.0.1')
    print('by Carsten Maartmann-Moe <carsten@carmaa.com> 2011\n')
    print('For updated, check out https://github.com/carmaa/FTWAutopwn')
    
    try:
        opts, args = getopt.getopt(argv, 'f:hlvt:d:n', ['file=', 'help', 'list' \
                                                        'verbose', \
                                                    'target=', 'delay=', 'no-write'])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-f', '--file'):
            ctx.file_mode = True
            ctx.file_name = str(arg)
        elif opt in ('-l', '--list'):
            unlock.list_targets(ctx.config)
            sys.exit()
        elif opt in ('-v', '--verbose'):
            ctx.verbose = True
        elif opt in ('-t', '--target'):
            ctx.target = unlock.select_target(ctx.config, int(arg))
        elif opt in ('-d', '--delay'):
            ctx.fw_delay = int(arg)
        elif opt in ('-n', '--no-write'):
            ctx.dry_run = True
        else:
            assert False, 'Unhandled option: ' + opt
    
    unlock.run(ctx)
        

if __name__ == '__main__':
    main(sys.argv[1:])
