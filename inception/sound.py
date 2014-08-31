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

Created on Oct 11, 2012

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import os.path
import subprocess

from inception import cfg


def play(filename):
    '''
    Crude interface for playing wav sounds - dies silently if something fails
    '''
    fn = filename
    f = os.path.join(os.path.dirname(__file__), fn)

    try:
        if (fn.endswith('.wav') or fn.endswith('.mp3')) and os.path.exists(f):
            if cfg.os == 'Linux':
                cmd = 'aplay'
            elif cfg.os == 'Darwin':
                cmd = 'afplay'
            else:
                raise Exception
            with open(os.devnull, "w") as fnull:
                return subprocess.Popen([cmd, f], stdout=fnull, stderr=fnull)
    except:
        raise
