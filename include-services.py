#!/usr/bin/env python

#imports
import os
import sys
import argparse
import csv
import re

VERSION = 0.1
WEB_URL = 'https://github.com/krishpranav/nmap-py'

def validate_file(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)
    
    return value

def validate_number(value):
    try:
        i = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('\'%s\' is not a number' % value)
    
    if i == -1:
        i = sys.maxint
    
    return i