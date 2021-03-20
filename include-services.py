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

def parse_arguments():
    parser = argparse.ArgumentParser(description='NmapPy services includer %.2f ( %s )' % (VERSION, WEB_URL))
    parser.add_argument('nmappy_file', action='store', type=validate_file, default='nmappy.py', nargs='?', help='File to patch')
    parser.add_argument('nmap_services_file', action='store', type=validate_file, default='nmap-services', nargs='?', help='nmap-services source file')
    parser.add_argument('-i', '--include', dest='number', action='store', type=validate_number, default=50, help='Number of TCP and UDP services to include (default: 50). Use -1 for all.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    return parser.parse_args()

