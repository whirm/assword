#!/usr/bin/env python

from distutils.core import setup

setup(
    name = 'assword',
    version = '0.0',
    description = 'Secure password database and retrieval system.',
    author = 'Jameson Rollins',
    author_email = 'jrollins@finestructure.net',
    url = '',
    py_modules = ['assword'],
    scripts = ['assword'],
    requires = [
        'gpgme',
        'getpass',
        'json',
        'base64',
        'urwid'
        ],
    )
