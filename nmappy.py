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

