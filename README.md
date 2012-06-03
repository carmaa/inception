Inception
=========

Inception is a FireWire physical memory manipulation and hacking tool
exploiting IEEE 1394 SBP-2 DMA. The tool can unlock (any password accepted)
and escalate privileges to Administrator/root on almost any machine you have
physical access to.

Inception aims to provide a stable and easy way of performing intrusive and 
non-intrusive memory hacks in order to unlock live computers using FireWire 
SBP-2 DMA. It it primarily attended to do its magic against computers that 
utilize full disk encryption such as BitLocker, FileVault, TrueCrypt or 
Pointsec. There are plenty of other (and better) ways to hack a machine that 
doesn't pack encryption.

As of version 0.1.3, it is able to unlock Windows XP SP2-3, Windows 7 SP0-1,
Vista SP0 and SP2, Mac OS X Snow Leopard and Lion, Ubuntu 11.04, 11.10 and 12.04
x86 and x64-bit machines and escalate privileges via the `runas` or `sudo -s`
commands, respectively. More signatures will be added. The tool makes extensive
use of the `libforensic1394`library courtesy of Freddie Witherden under a LGPL
license.


Key data
--------

 * Version: 0.1.4
 * License: GPL
 * Author: 	Carsten Maartmann-Moe (carsten@carmaa.com) AKA ntropy (n@tropy.org)
 * Twitter: @breaknenter Hashtag: #inceptiontool
 * Site: 	http://www.breaknenter.org/projects/inception
 * Source: 	https://github.com/carmaa/inception


Requirements
------------

Inception requires:

 * Linux or Mac OS X
 * Python 3 (http://www.python.org)
 * libforensic1394 (https://freddie.witherden.org/tools/libforensic1394/)
 * A FireWire or Thunderbolt interface, or an ExpressCard/PCMCIA expansion port


Installation
------------

For now you should be able to run the tool without any installation except
dependencies on Mac OS X and Linux distros. Check out the README file in 
`libforensic1394` for installation and FireWire pro-tips.

On Debian-based distributions the installation command lines can be summarized
as:

### Download and install dependencies

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

### Download and install Inception

	git clone https://github.com/carmaa/inception.git
	cd inception
	sudo python3 setup.py install


Usage
-----

To run it, simply type (as root if required by your OS):

	incept

For a more complete and up-to-date description, please see the tool home page 
at http://www.breaknenter.org/projects/inception.


Known bugs / caveats
--------------------

Please see the tool home page at http://www.breaknenter.org/projects/inception/#Known_bugs.
   

Troubleshooting
---------------

Please see the tool home page at http://www.breaknenter.org/projects/inception/#Troubleshooting.


Planned features
----------------

 * Insert and execute memory-only rootkit
 * Other winlockpwn techniques
 * Extraction of AES (and perhaps Serpent and Twofish) encryption keys
 * Extraction of NTLM/LM hashes
 * Extraction of passwords
 
 
Development history
-------------------
 
 * 0.0.1 - First version, supports basic Windows XP SP3, Vista and 7, Mac OS X
           and Ubuntu Gnome unlocking  
 * 0.0.2 - Added signatures for early XP SP3, and Windows 7 x86 and x64 SP1  
 * 0.0.3 - Added some signatures (thanks Tekkenhead) and error handling  
 * 0.0.4 - Added businfo to display connected FireWire devices as well as memory
           dumping capabilities  
 * 0.0.5 - Enhanced memory dumping abilities and added samples catalog  
 * 0.0.6 - Added unit testing  
 * 0.0.7 - Updated Ubuntu signatures and priv. escalation - thanks Adel Khaldi
           from Algeria  
 * 0.0.8 - Fixed Ubuntu unlock and privilege escalation patches - single patch
           for double the action
 * 0.1.0 - First minor version! Added signatures for OS X and Vista, plus quite
           a few bug fixes
 * 0.1.1 - Added signatures for Ubuntu 12.04 LTS
 * 0.1.2 - Patched several bugs
 * 0.1.3 - Patched OS X 10.6.8 x64 signature bug
 * 0.1.4 - Added manual mode easing testing of new signatures
 
 
Disclaimer
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your pythonesque purity senses, drop me a note on how
I can improve it. Or even better, fork my code, change it and issue a pull
request.