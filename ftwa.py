#!/usr/bin/env python3
'''
Created on Oct 15, 2011

@author: carsten
'''
import sys
import getopt
import ftwautopwn.settings as settings
from ftwautopwn.util import msg, fail
from ftwautopwn import screenlock
import os


def main(argv):
    settings.encoding = sys.getdefaultencoding()
    
    # Load available JSON targets - not in use per today
    #===========================================================================
    # configuration = open(settings.configfile, 'r')
    # targets = json.load(configuration)
    # configuration.close()
    #===========================================================================
    targets = settings.targets
    
    # Print banner
    print('''
Fire Through the Wire Autopwn (FTWA) v.0.1.0
by Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org> 2012

For updates, check/clone https://github.com/carmaa/FTWAutopwn
''')
    
    try:
        opts, args = getopt.getopt(argv, 
                                   'd:f:hilvt:w:n', 
                                   ['dump=', 'file=', 'help', 'interactive', 
                                    'list'  'verbose', 'technique=', 'wait=', 
                                    'no-write'])
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
            fail("Option not implemented yet, sorry.")
        elif opt in ('-w', '--wait'):
            settings.fw_delay = int(arg)
        elif opt in ('-n', '--no-write'):
            settings.dry_run = True
        elif opt in ('-d', '--dump'):
            settings.memdump = True
            start, end = int(str(arg).split(','))
            settings.dumpstart = start
            settings.dumpend = end
        elif opt in ('-i', '--interactive'):
            settings.interactive = True
            # TODO
            fail("Option not implemented yet, sorry.")
        else:
            assert False, 'Option not handled: ' + opt
    
    if not settings.filemode and not os.geteuid() == 0:
        fail("You must be root to run FTWA with FireWire input.")
    
    # TODO: Detect devices
    
    screenlock.attack(targets)
    
    
def usage(execname):
    print('''Usage: ''' + execname + ''' [OPTIONS]

Attack machines over the IEEE1394 interface by exploiting SBP-2 DMA.

    -d, --dump=START,END  Dump memory from START address to END address. By
                          default, all pages are dumped. Memory content is
                          dumped to files with the file name syntax:
                          'ftwamemdump_START-END.bin'
    -f, --file=FILE:      Use a file instead of FireWire bus data as input; for
                          example to facilitate attacks on VMware machines or
                          to ease testing and signature generation efforts
    -h, --help:           Displays this message
    -i, --interactive     Interactive mode. Use this to search for specific
                          signatures at specific offsets
    -l, --list:           Lists available target operating systems
    -n, --no-write:       Dry run, do not write back to memory
    -t TARGET, --technique=TARGET:
                          Specify target operating system (use --list to list 
                          available targets)
    -v, --verbose:        Verbose mode
    -wait, --wait=TIME:   Delay attack by TIME seconds. This is useful in order
                          to guarantee that the target machine has successfully
                          granted the host DMA before attacking. If the
                          attack fails, try to increase this value. Default
                          delay is 15 seconds.''')
    

if __name__ == '__main__':
    main(sys.argv[1:])