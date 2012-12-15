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

The tool works over any interface that expands and can master the PCIe bus. This
includes FireWire, Thunderbolt, ExpressCard and PCMCIA (PC-Card).

As of version 0.2.3, it is able to unlock the following x86 and x64 operating
systems:

|OS           |Version        |Unlock lock screen|Escalate privileges|Dump memory < 4 GiB|
|:------------|:--------------|:----------------:|:-----------------:|:-----------------:|
|Windows 8    |SP0            |        Yes       |        Yes        |        Yes        |
|Windows 7    |SP1            |        Yes       |        Yes        |        Yes        |
|Windows 7    |SP0            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP2            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP1            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP0            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP3            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP2            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP1            |                  |                   |        Yes        |
|Windows XP   |SP0            |                  |                   |        Yes        |
|Mac OS X     |Mountain Lion  |       Yes (1)    |       Yes (1)     |       Yes (1)     |
|Mac OS X     |Lion           |       Yes (1)    |       Yes (1)     |       Yes (1)     |
|Mac OS X     |Snow Leopard   |        Yes       |        Yes        |        Yes        |
|Mac OS X     |Leopard        |                  |                   |        Yes        |
|Ubuntu (2)   |Quantal (12.10)|        Yes       |        Yes        |        Yes        |
|Ubuntu       |Precise (12.04)|        Yes       |        Yes        |        Yes        |
|Ubuntu       |Oneiric (11.10)|        Yes       |        Yes        |        Yes        |
|Ubuntu       |Natty (11.04)  |        Yes       |        Yes        |        Yes        |
|Linux Mint   |13             |        Yes       |        Yes        |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |        Yes        |

(1) If FileVault 2 is enabled, the tool will only work when the operating
    system is unlocked.
(2) Other Linux distributions that use PAM-based authentication may also work 
    using the Ubuntu signatures.

The tool also effectively enables escalation of privileges via the `runas` or 
`sudo -s` commands, respectively. More signatures will be added. The tool makes
use of the `libforensic1394` library courtesy of Freddie Witherden under a LGPL
license.


Key data
--------

 * Version:	0.2.3
 * License:	GPL
 * Author:	Carsten Maartmann-Moe (carsten@carmaa.com) AKA ntropy (n@tropy.org)
 * Twitter:	@breaknenter Hashtag: #inceptiontool
 * Site:	http://www.breaknenter.org/projects/inception
 * Source:	https://github.com/carmaa/inception


Requirements
------------

Inception requires:

 * Linux or Mac OS X (host / attacker machine)
 * A FireWire or Thunderbolt interface, or an ExpressCard/PCMCIA expansion port


Installation
------------

For now you should be able to run the tool without any installation except
dependencies on Mac OS X and Linux distros. Check out the README file in 
`libforensic1394` for installation and FireWire pro-tips.

### Dependencies

 * Python 3		(http://www.python.org)
 * git			(http://git-scm.com)
 * gcc (incl. g++)	(http://gcc.gnu.org)
 * cmake		(http://www.cmake.org)
 * libforensic1394	(http://freddie.witherden.org/tools/libforensic1394/)

On Debian-based distributions the installation command lines can be summarized
as:

### Download and install dependencies

	sudo apt-get install git cmake python3 g++
	wget http://freddie.witherden.org/tools/libforensic1394/releases/libforensic1394-0.2.tar.gz
	tar xvf libforensic1394-0.2.tar.gz
	cd libforensic1394-0.2
	cmake CMakeLists.txt
	sudo make install
	cd python
	sudo python3 setup.py install

### Download and install Inception

	git clone https://github.com/carmaa/inception.git
	cd inception
	sudo setup.py install


Usage
-----

 1. Connect the attacker machine (host) and the victim (target) with a FireWire cable
 2. Run Inception

Simply type (as root if required by your OS):

	incept

For a more complete and up-to-date description, please run:

	incept -h

or see the tool home page at http://www.breaknenter.org/projects/inception.


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
 * 0.2.0 - Added signatures for OS X Mountain Lion (10.8) and Windows 8
 * 0.2.1 - Added signatures for Ubuntu 12.10
 * 0.2.2 - Added signatures for Linux Mint
 * 0.2.3 - General code cleanup, and nicer and more consistent output
 
 
Disclaimer
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your pythonesque purity senses, drop me a note on how
I can improve it. Or even better, fork my code, change it and issue a pull
request.
