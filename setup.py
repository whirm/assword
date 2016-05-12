#!/usr/bin/env python3

from distutils.core import setup

setup(
    name = 'assword',
    version = '0.8',
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
        'pkg_resources',
        ],
    )
