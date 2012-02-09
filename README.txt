CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Requirements
 * Installation
 * Usage
 * Known bugs
 * Troubleshooting
 * Planned features
 * Disclaimer


INTRODUCTION
------------

Name: Inception
Version: 0.0.6
License: GPL
Author: Carsten Maartmann-Moe <carsten@carmaa.com> AKA ntropy <n@tropy.org>
Twitter: @breaknenter Hashtag: #inceptiontool
Site: http://www.breaknenter.org/projects/inception
Source: https://github.com/carmaa/inception

Inception is a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Inception aims to provide a stable and easy way of performing intrusive and 
non-intrusive memory hacks in order to unlock live computers using FireWire 
SBP-2 DMA. It it primarily attended to do its magic against computers that 
utilize full disk encryption such as BitLocker, FileVault, TrueCrypt or 
Pointsec. There are plenty of other (and better) ways to hack a machine that 
doesn’t pack encryption.

As of version 0.0.5, it is able to unlock Windows XP SP2-3, Windows 7 x32 and 
x64-bit machines. More signatures will be added. The tool makes extensive use 
of the libforensic1394 library courtesy of Freddie Witherden under a LGPL 
license.


REQUIREMENTS
------------

Inception requires:

 * Python 3 (http://www.python.org)
 * libforensic1394 (https://freddie.witherden.org/tools/libforensic1394/)


INSTALLATION
------------

For now you should be able to run the tool without any installation except
dependencies on Mac OS X and Linux distros. Check out the README file in 
libforensic1394 for installation and FireWire pro-tips. I'll add the setup.py
packaging at a later stage.

On Debian-based distros the installation command lines can be summarized as:

sudo apt-get install git cmake python3
wget https://freddie.witherden.org/tools/libforensic1394/releases/libforensic1394-0.2.tar.gz
tar xvf libforensic1394-0.2.tar.gz
cd libforensic1394-0.2
mkdir build
cd build
cmake -G"Unix Makefiles" ../
make
sudo make install
cd ../python
sudo python3 setup.py install

git clone https://github.com/carmaa/inception.git
cd inception
python3 setup.py install

On BackTrack and some other configurations, you may have to set LD_LIBRARY path
to /usr/local/lib to make it find the libforensics1394 libs:

export LD_LIBRARY_PATH=/usr/local/lib

To permanently fix this, copy the libforensics1394 libs from /usr/local/lib to 
/usr/lib.


USAGE
-----

To run it, simply type (as root if required by your OS):

incept

For a more complete and up-to-date descriptiton, please see the tool home page 
at http://www.breaknenter.org/projects/inception



KNOWN BUGS / CAVEATS
--------------------

Please see the tool home page at http://www.breaknenter.org/projects/inception
   

TROUBLESHOOTING
---------------

Please see the tool home page at http://www.breaknenter.org/projects/inception


PLANNED FEATURES
----------------

 * Patch signatures for Windows XP, Mac OS X and Ubuntu
 * Increased signature stability on Windows x64 arch
 * Other winlockpwn techniques
 * Complete memory (RAM) dumps
 * Extraction of AES (and perhaps Serpent and Twofish) encryption keys
 * Extraction of NTLM/LM hashes
 * Extraction of passwords
 
 
DEVELOPMENT HISTORY
-------------------
 
 0.0.1 - First version, supports basic Windows XP SP3, Vista and 7, Mac OS X and
         Ubuntu Gnome unlocking
 0.0.2 - Added signatures for early XP SP3, and Windows 7 x86 and x64 SP1
 0.0.3 - Added some signatures (thanks Tekkenhead) and error handling
 0.0.4 - Added businfo to display connected FireWire devices as well as memory
         dumping capabilities
 0.0.5 - Enhanced memory dumping abilities and added samples catalog
 
 
DISCLAIMER
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your pythonesque purity senses, drop me a note on how
I can improve it. Or even better, fork my code, change it and issue a pull
request.