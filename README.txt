
CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Requirements
 * Installation
 * Usage
 * Planned features


INTRODUCTION
------------

Name: FTWAutopwn
Version: 0.0.1 (pre-alpha)
License: GPL
Author: Carsten Maartmann-Moe <carsten@carmaa.com> AKA ntropy <n@tropy.org>
Twitter: breaknenter
Blog: http://www.breaknenter.org

Fire Through the Wire Autopwn (FTWAutopwn) was originally coded as a replacement
for winlockpwn, the Windows FireWire unlock tool made available by Metlstorm. As
winlockpwn was quite stable against Windows XP targets, but not so against
Windows 7 and more modern operating systems, and the tool is not maintained
anymore, FTWAutopwn was born.

FTWAutopwn aims to provide a stable and easy way of performing intrusive and
non-intrusive memory analysis on live machines using FireWire SBP2 DMA.

As of version 0.0.1, it is able to unlock Windows 7 32 and 64-bit machines. More
signatures will be added rapidly.

The tool makes extensive use of the libforensic1394 library provided by Freddie
Witherden on a LGPL license.

REQUIREMENTS
------------

FTWAutopwn requires:

 * Python 3.2 (http://www.python.org)
 * libforensic1394 (https://freddie.witherden.org/tools/libforensic1394/)

INSTALLATION
------------

For now you should be able to run the tool without any installation on Mac OS X
and Linux distros. I'll add the setup.py packaging at a later stage.


USAGE
-----

To run it, simply type (as root if required by your OS):

python3 ftwautopwn.py

The tool automatically uses config.cfg as a config file, but you can specify
your own config file if you want to. The config file contains a simple, .ini-
style syntax defining search signatures, patches and offsets.


PLANNED FEATURES
----------------

 * Patch signatures for Windows XP, Mac OS X and Ubuntu
 * Complete memory (RAM) dumps
 * Extraction of AES, Serpent and Twofish encryption keys
 * Extraction of NTLM/LM hashes
 * Extraction of passwords