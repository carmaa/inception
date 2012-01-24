
CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Requirements
 * Installation
 * Usage
 * Known bugs
 * Troubleshooting
 * Planned features


INTRODUCTION
------------

Name: FTWAutopwn
Version: 0.0.2
License: GPL
Author: Carsten Maartmann-Moe <carsten@carmaa.com> AKA ntropy <n@tropy.org>
Twitter: breaknenter
Site: http://www.breaknenter.org/projects/ftwautopwn

Fire Through the Wire Autopwn (FTWAutopwn) was originally coded as a replacement
for winlockpwn, the Windows FireWire unlock tool made available by Metlstorm. As
winlockpwn was quite stable against Windows XP targets, but not so against
Windows 7 and more modern operating systems, and the tool is not maintained
anymore. As of Ubuntu 11.04 the shipped Linux uses the new FireWire stack, 
making winlockpwn obsolete. Alas, FTWAutopwn was born.

FTWAutopwn aims to provide a stable and easy way of performing intrusive and
non-intrusive memory analysis on live machines using FireWire SBP2 DMA.

As of version 0.0.1, it is able to unlock Windows 7 32 and 64-bit machines. More
signatures will be added.

The tool makes extensive use of the libforensic1394 library provided by Freddie
Witherden on a LGPL license.


REQUIREMENTS
------------

FTWAutopwn requires:

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
git clone https://github.com/carmaa/FTWAutopwn.git
cd FTWAutopwn
python3 ftwautopwn.py

On BackTrack and some other configurations, you may have to set LD_LIBRARY path
to /usr/local/lib to make it find the libforensics1394 libs:

export LD_LIBRARY_PATH=/usr/local/lib

To permanently fix this, copy the libforensics1394 libs from /usr/local/lib to 
/usr/lib.


INSTALLATION ON BACKTRACK 5.x
-----------------------------

Courtesy of Glenn P. Edwards Jr., I've bundled a nice shell script that should
automagically take care of the above commands. Run ./bt5-setup.sh to set up and
run FTWA on BT5.


USAGE
-----

To run it, simply type (as root if required by your OS):

python3 ftwautopwn.py

The tool automatically uses config.cfg as a config file, but you can specify
your own config file if you want to. The config file contains a simple, .ini-
style syntax defining search signatures, patches and offsets.

The experimental version can be run by:

./ftwa.py


KNOWN BUGS / CAVEATS
--------------------

 * For some reason, it is broken on Mac OS X Lion
 * x64 signatures are unstable, and currently the signature only matches a
   single Patch version of the msv1_0.dll. You might be lucky and have the same
   version on your target, so it's not entirely unuseful, though
 * Because of how physical memory is mapped at the hardware level, you may
   experience trouble  memory over 2 GiB on machines with 4 GiB or more main
   memory
   

TROUBLESHOOTING
---------------
Please see the tool home page at http://www.breaknenter.org/projects/ftwautopwn


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
 0.0.4 - Added businfo to display connected FireWire devices