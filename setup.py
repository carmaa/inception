#!/usr/bin/env python3
'''
Created on Jun 18, 2011

@author: carmaa
'''

# Inception's setup.py
from distutils.core import setup
from inception import cfg

setup(
    name = 'inception',
    packages = ['inception'],
    scripts = ['incept'],
    package_data= {'inception': ['resources/oui.txt', 
                                 'resources/inception.wav']},
    version = cfg.version,
    description = 'Memory manipulation tool exploiting FireWire SBP2 DMA.',
    author = 'Carsten Maartmann-Moe',
    author_email = 'carsten@carmaa.com',
    url = cfg.url,
    download_url = 'http://github.com/carmaa/inception',
    license = 'GPL',
    requires = ['forensic1394'],
    keywords = ['hack', 'physical security', 'firewire'],
    classifiers = [
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.2',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Security experts',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Topic :: Security']
)
