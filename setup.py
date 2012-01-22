'''
Created on Jun 18, 2011

@author: carmaa
'''

# ftwautopwn's setup.py
from distutils.core import setup
setup(
    name = "FTWAutopwn",
    packages = ["ftwautopwn"],
    version = "0.0.1",
    description = "Autopwnage tool exploiting FireWire SBP2 DMA.",
    author = "Carsten Maartmann-Moe",
    author_email = "carsten@carmaa.com",
    url = "http://www.breaknenter.org/",
    download_url = "",
    keywords = ["hack", "physical security", "xml"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.2",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Security experts",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: OS Independent",
        "Topic :: Security",
        ],
    long_description = """\
Fire Through the Wire Autopwn
----------------------------

TODO

This version requires Python 3 or later.
"""
)