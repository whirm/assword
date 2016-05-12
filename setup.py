#!/usr/bin/env python3

from distutils.core import setup

version = {}
with open("assword/version.py") as f:
    exec(f.read(), version)

setup(
    name = 'assword',
    version = version['__version__'],
    description = 'Secure password management and retrieval system.',
    author = 'Jameson Rollins',
    author_email = 'jrollins@finestructure.net',
    url = 'https://finestructure.net/assword',
    py_modules = ['assword'],
    scripts = ['assword'],
    requires = [
        'gpgme',
        'getpass',
        'json',
        'base64',
        'gi',
        ],
    )
