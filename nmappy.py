#!/usr/bin/env python

#imports
import argparse
import socket
import sys
import os.path
import csv
import string
import random
import subprocess
import re
from datetime import datetime
from netaddr import *

VERSION = 0.51
WEB_URL = 'https://github.com/krishpranav/nmap-py'
MAX_RESULTS_DISPLAY = 30
ALL_SERVICES_INCLUDED = False


def target_spec(value):
    targets = {}
    octets = value.split('.')

    # IP address is specified
    contains_invalid_char = [char not in string.digits + '/-,' for octet in octets for char in octet]
    if len(octets) == 4 and True not in contains_invalid_char:
        # - 192.168.0.0/24
        if '/' in octets[3]:
            cidr = IPNetwork(value)
            targets = {key: None for key in [str(ip) for ip in cidr[1:-1]]}
        # - 192.168.0.1-254
        elif '-' in octets[3]:
            (ip_start, ip_end) = map(int, octets[3].split('-'))
            targets = {key: None for key in
                            ['.'.join(octets[0:3] + [str(host)]) for host in xrange(ip_start, ip_end + 1)]}
        # 192.168.0.1,103,104
        elif ',' in octets[3]:
            targets = {key: None for key in
                            ['.'.join(octets[0:3] + [str(host)]) for host in octets[3].split(',')]}
        # - 192.168.0.*
        # - 192.168.*.*
        elif '*' in octets:
            ips = [[i for i in xrange(1, 255)] if octet == '*' else [octet] for octet in octets]
            targets = {key: None for key in
                            ['.'.join(map(str, [a, b, c, d])) for a in ips[0] for b in ips[1] for c in ips[2] for d in
                             ips[3]]}
        # - 192.168.0.1
        else:
            targets = {value: None}
    # Hostname is specified
    # - myserver.me
    else:
        targets = {value: None}

    return targets

def check_file_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)

    return value

def read_input_list(args):
    targets = {}
    with open(args.input_filename, 'r') as input:
        for line in input:
            dict.update(targets, target_spec(line.strip()))
    
    return targets

def scan_technique(value):
    if value == 'U':
        raise argparse.ArgumentTypeError('UDP is not supported at this moment')
    if len(value) > 1:
        raise argparse.ArgumentTypeError('Current a combination of TCP and UDP is not supported')
    
    return value

def port_specification(value):
    ports = []
    if len(value) > 0:
        for part in value.split(','):
            if '-' in part:
                range = map(int, part.split('-'))
                for p in xrange(range[0], range[1] + 1):
                    ports.append(p)
            else:
                ports.append(int(part))

    return ports

def output_validate(value):
    if value == 'X':
        raise argparse.ArgumentTypeError('Currently the XML output option is not supported')
    
    return value


def parse_arguments():
    parser = argparse.ArgumentParser(description='NmapPy %.2f ( %s )' % (VERSION, WEB_URL), add_help=False)

    # TARGET SPECIFICATION
    target = parser.add_argument_group('TARGET SPECIFICATION')
    input_options = target.add_mutually_exclusive_group(required=True)
    input_options.add_argument('targets',                       action='store', nargs='?', type=target_spec, help='Can pass hostnames, IP addresses, networks, etc.')
    input_options.add_argument('-iL',   dest='input_filename',  action='store', nargs='?', type=check_file_exists, default=None, help='Input from list of hosts/networks')

    # HOST DISCOVERY
    discovery = parser.add_argument_group('HOST DISCOVERY')
    discovery.add_argument('-Pn',       dest='skip_host_discovery', action='store_true', help='Treat all hosts as online -- skip host discovery')
    discovery.add_argument('-sn',       dest='ping_scan',       action='store_true', help='Ping Scan - disable port scan')

    # SCAN TECHNIQUES
    scantech = parser.add_argument_group('SCAN TECHNIQUES')
    scantech.add_argument('-s',         dest='scan_technique',  action='store', type=scan_technique, choices='TU', default='T', help='TCP Connect()/UDP scan (not implemented)')

    # PORT SPECIFICATION AND SCAN ORDER
    portspec = parser.add_argument_group('PORT SPECIFICATION AND SCAN ORDER')
    portspec.add_argument('-p',         dest='ports',           action='store', type=port_specification, help='Only scan specified ports')
    portspec.add_argument('--top-ports',dest='top_ports',       action='store', type=int, default=1000, help='Scan <number> most common ports')
    portspec.add_argument('-F',         dest='top_ports',       action='store_const', default=False, const=100, help='Fast mode - Scan fewer ports than the default scan')
    portspec.add_argument('-r',         dest='ports_randomize', action='store_false', help='Scan ports consecutively - don\'t randomize')

    # SERVICE/VERSION DETECTION
    # -

    # SCRIPT SCAN
    # -

    # OS DETECTION
    # -

    # TIMING AND PERFORMANCE
    performance = parser.add_argument_group('TIMING AND PERFORMANCE')
    performance.add_argument('-T',      dest='timing',          action='store', type=int, choices=[i for i in xrange(1,6)], default=3, help='Set timing template (higher is faster)')

    # FIREWALL/IDS EVASION AND SPOOFING
    # -

    # OUTPUT
    output = parser.add_argument_group('OUTPUT')
    output.add_argument('-v',           dest='verbosity',       action='count', default=0, help='Increase verbosity level (use -vv or more for greater effect)')
    output.add_argument('-o',           dest='output_type',     action='store', choices='NX', type=output_validate, help='Output scan in normal/XML (not implemented)')
    output.add_argument('output_file',  help='File name/location', nargs='?')

    # MISC
    misc = parser.add_argument_group('MISC')
    misc.add_argument('-h', '--help', action='help', help='Print this help summary page.')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()
