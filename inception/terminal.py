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

Created on Sep 6, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
import os
import subprocess
import sys
import textwrap
import time

import binascii
from inception import cfg


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(
                *args, **kwargs)
        return cls._instances[cls]


class Terminal(metaclass=Singleton):
    
    def __init__(self):
        self.wrapper = textwrap.TextWrapper(subsequent_indent=' ' * 4,
                                            replace_whitespace=False)
        self.wrapper.width = self.width()

    def width(self):
        '''
        Returns the size (width) of the terminal
        '''
        try:
            with open(os.devnull, 'w') as fnull:
                r, c = subprocess.check_output(['stty', 'size'],
                                               stderr=fnull).split()
            return int(c)
        except:
            self.warn('Cannot detect terminal column width')
            return 80
        
    def write(self, s, indent=True, end_newline=True):
        '''
        Prints a line and wraps each line at terminal width
        '''
        if not indent:
            # Save default indent
            default_indent = self.wrapper.subsequent_indent
            self.wrapper.subsequent_indent = ''
        wrapped = '\n'.join(self.wrapper.wrap(str(s)))
        if not end_newline:
            print(wrapped, end=' ')
        else:
            print(wrapped)
        if not indent:
            # Restore default indent
            self.wrapper.subsequent_indent = default_indent

    def info(self, s, sign='*'):
        '''
        Print an informational message with '*' as a sign
        '''
        self.write('[{0}] {1}'.format(sign, s))

    def poll(self, s, sign='?', default='', newline=False):
        '''
        Prints a question to the user. Returns the answer, in lower case
        '''
        self.write('[{0}] {1}'.format(sign, s), end_newline=newline)
        user_input = input('{0}'.format(default + chr(8) * len(default)))
        if not user_input:
            user_input = default
        return user_input.lower()

    def found_at(self, address, page):
        '''
        Print a sig found message
        '''
        self.info('Signature found at {0:#x} in page no. {1}'
                  .format(address, page))
    
    def warn(self, s, sign='!'):
        '''
        Prints a warning message with '!' as a sign
        '''
        self.write('[{0}] Warning: {1}'.format(sign, s))

    def error(self, s, sign='-'):
        '''
        Prints a warning message with '!' as a sign
        '''
        self.write('[{0}] Error: {1}'.format(sign, s))

    def wait(self, s, seconds):
        '''
        Wait x seconds and display a BeachBall while doing so
        '''
        bb = self.BeachBall(s)
        start = time.time()
        while time.time() - start < seconds:
            bb.draw()
            time.sleep(0.1)
        print()  # New line

    class ProgressBar:
        '''
        Builds and displays a text-based progress bar
        
        Based on https://gist.github.com/3306295
        '''

        def __init__(self, min_value=0, max_value=100, total_width=80,
                     print_data=True):
            '''
            Initializes the progress bar
            '''
            self.progbar = ''   # This holds the progress bar string
            self.old_progbar = ''
            self.min = min_value
            self.max = max_value
            self.span = max_value - min_value
            self.width = total_width - len(' 4096 MiB (100%)')
            self.unit = cfg.MiB
            self.unit_name = 'MiB'
            self.print_data = print_data
            if self.print_data:
                self.data_width = total_width // 5
                if self.data_width % 2 != 0:
                    self.data_width = self.data_width + 1
                self.width = self.width - (len(' {}') + self.data_width)
            else:
                self.data_width = 0
            self.amount = 0  # When amount == max, we are 100% done
            self.update_amount(0)  # Build progress bar string

        def append_amount(self, append):
            '''
            Increases the current amount of the value of append and
            updates the progress bar to new ammount
            '''
            self.update_amount(self.amount + append)
        
        def update_percentage(self, new_percentage):
            '''
            Updates the progress bar to the new percentage
            '''
            self.update_amount((new_percentage * float(self.max)) / 100.0)
            
        def update_amount(self, new_amount=0, data=b'\x00'):
            '''
            Update the progress bar with the new amount (with min and max
            values set at initialization; if it is over or under, it takes the
            min or max value as a default
            '''
            if new_amount < self.min:
                new_amount = self.min
            rel_amount = new_amount - self.min
            if new_amount > self.max:
                new_amount = self.max
            self.amount = new_amount

            # Figure out the new percent done, round to an integer
            diff_from_min = float(self.amount - self.min)
            percent_done = (diff_from_min / float(self.span)) * 100.0
            percent_done = int(round(percent_done))

            # Figure out how many hash bars the percentage should be
            all_full = self.width - 2
            num_hashes = (percent_done / 100.0) * all_full
            num_hashes = int(round(num_hashes))

            # Build a progress bar with an arrow of equal signs; special cases
            # for empty and full
            if num_hashes == 0:
                self.progbar = '[>{0}]'.format(' ' * (all_full - 1))
            elif num_hashes == all_full:
                self.progbar = '[{0}]'.format('=' * all_full)
            else:
                self.progbar = '[{0}>{1}]'.format(
                    '=' * (num_hashes - 1),
                    ' ' * (all_full - num_hashes))

            # Generate string
            percent_str = '{0:>4d} {1} ({2:>3}%)'.format(
                rel_amount // self.unit,
                self.unit_name,
                percent_done)
            
            # If we are to print data, append it
            if self.print_data:
                data_hex = bytes.decode(binascii.hexlify(data))
                data_str = ' {{{0:0>{1}.{1}}}}'.format(
                    data_hex, self.data_width)
                percent_str = percent_str + data_str

            # Slice the percentage into the bar
            self.progbar = ' '.join([self.progbar, percent_str])
        
        def draw(self):
            '''
            Draws the progress bar if it has changed from it's previous value
            '''
            if self.progbar != self.old_progbar:
                self.old_progbar = self.progbar
                sys.stdout.write(self.progbar + '\r')
                sys.stdout.flush()  # force updating of screen

        def __str__(self):
            '''
            Returns the current progress bar
            '''
            return str(self.progbar)
        
    class BeachBall:
        '''
        An ASCII beach ball
        '''
        
        def __init__(self, s, max_frequency=0.1):
            self.states = ['-', '\\', '|', '/']
            self.state = 0
            self.max_frequency = max_frequency
            self.time_drawn = time.time()
            self.s = s
            
        def draw(self, force=False):
            '''
            Draws the beach ball if the time delta since last draw is greater
            than the max_frequency
            '''
            now = time.time()
            if self.max_frequency < now - self.time_drawn or force:
                self.state = (self.state + 1) % len(self.states)
                print('[{0}] {1}\r'.format(self.states[self.state],
                                           self.s), end='')
                sys.stdout.flush()
                self.time_drawn = now
