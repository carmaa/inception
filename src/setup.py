'''
Created on Jun 18, 2011

@author: carmaa
'''

# chardet's setup.py
from distutils.core import setup
setup(
    name = "FTWAutopwn",
    packages = ["ftwautopwn"],
    version = "0.0.1",
    description = "Autopwnage tool exploiting FireWire SBP2 DMA.",
    author = "Carsten Maartmann-Moe",
    author_email = "carsten@carmaa.com",
    url = "http://www.breaknenter.org/",
    download_url = "http://chardet.feedparser.org/download/python3-chardet-1.0.1.tgz",
    keywords = ["hack", "physical security", "xml"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Security experts",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Linguistic",
        ],
    long_description = """\
Fire Through the Wire Autopwn
----------------------------

TODO

This version requires Python 3 or later; a Python 2 version is available separately.
"""
)