#!/usr/bin/env python

from distutils.core import setup

setup(
    name = 'assword',
    version = '0.7',
    description = 'Secure password management and retrieval system.',
    author = 'Jameson Rollins',
    author_email = 'jrollins@finestructure.net',
    url = 'http://finestructure.net/assword',
    py_modules = ['assword'],
    scripts = ['assword'],
    requires = [
        'gpgme',
        'getpass',
        'json',
        'base64',
        'gtk2',
        'pkg_resources',
        ],
    )
