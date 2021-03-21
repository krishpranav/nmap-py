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


# SCAN TECHNIQUES
# Implemented: -sT, -sU
# URL: https://nmap.org/book/man-port-scanning-techniques.html
def scan_technique(value):
    if value == 'U':
        raise argparse.ArgumentTypeError('UDP is not supported at this moment.')
    if len(value) > 1:
        raise argparse.ArgumentTypeError('Currently a combination of TCP and UDP is not supported.')

    return value


# PORT SPECIFICATION AND SCAN ORDER
# Implemented: -p, --top-ports
# URL: https://nmap.org/book/man-port-specification.html
def port_specification(value):
    ports = []
    # Use specified ports
    if len(value) > 0:
        for part in value.split(','):
            # Port range
            if '-' in part:
                range = map(int, part.split('-'))
                for p in xrange(range[0], range[1] + 1):
                    ports.append(p)
            # Single port
            else:
                ports.append(int(part))

    return ports


# OUTPUT
# Implemented: -oN
# URL: https://nmap.org/book/man-output.html
def output_validate(value):
    if value == 'X':
        raise argparse.ArgumentTypeError('Currently the XML output option is not supported.')

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


def ping(ip, timing):
    # Windows (win32)
    if sys.platform == 'win32':
        cmd = ['ping', '-n', '1', '-w', str(2000/timing), ip]
        # Success: Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
        # Fail: Request timed out.
        pattern = '^Reply from ([0-9]{1,3}\.?){4}: bytes=[0-9]+ time[=<]?(?P<MS>([0-9]+))ms TTL=[0-9]+\r$'
    # Linux (linux2)
    else:
        cmd = ['timeout', '%.2f' % (2.0/timing), 'ping', '-s', '24', '-c', '1', ip]
        # Success: 1 packets transmitted, 1 received, 0% packet loss, time 0ms
        # Fail: [empty]
        pattern = '^1 packets transmitted, 1 received, 0% packet loss, time (?P<MS>([0-9]+))ms$'

    # Execute command
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = process.communicate()[0]

    # Extract milliseconds from output
    ms = -1
    m = re.search(pattern, output, flags=re.MULTILINE)
    if m is not None:
        ms = int(m.group('MS'))

    # Exit process
    process.wait()

    return ms


def check_port(host, proto, port, timeout):
    result = False
    try:
        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(1.0/timeout)
        r = sock.connect_ex((host, port))

        if r == 0:
            result = True

        sock.close()
    except Exception:
        pass

    return result


def read_services():
    # Read services from file, if available; otherwise the (limited) built-in list will be used
    if not ALL_SERVICES_INCLUDED and os.path.isfile('nmap-services'):
        sfile = csv.reader(open('nmap-services', 'r'), dialect='excel-tab')
        global services
        services = []
        for s in sfile:
            if not str(s[0]).startswith('#'):
                services.append((s[1], s[0], s[2]))

        services = sorted(services, key=lambda s: s[2], reverse=True)

    # Process list for easier usage
    for s in services:
        (port, proto) = str(s[0]).split('/')
        (port, proto) = (int(port), proto)
        services_lookup[proto][port] = s[1]
        services_top[proto].append(port)


def configure_scan(args):
    # If -iL (input list) is provided, fill targets based on this
    if args.input_filename is not None:
        args.targets = read_input_list(args)

    # Determine protocol based on Port Scanning Technique
    if args.scan_technique == 'T':
        args.proto = 'tcp'
    else:
        args.proto = 'udp'

    # In case no ports are provided, use top-ports
    if not args.ports:
        ports = []
        for s in services_top[args.proto]:
            ports.append(s)

            if len(ports) == args.top_ports:
                break

        args.ports = ports

    # Randomize order of ports
    if args.ports_randomize:
        random.shuffle(args.ports)

    # Output
    if args.output_type == 'N':
        try:
            f = open(args.output_file, 'w', 0)
            args.output = f
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            sys.exit(1)
    else:
        args.output = None


def finish_scan(args):
    # Close output file handle
    if args.output:
        args.output.close()


def print_line(line, output):
    print line

    if output:
        output.write(line + '\n')


def main():
    # Check validity of commandline arguments
    args = parse_arguments()

    # Prepare services list
    read_services()

    # Configure scan
    configure_scan(args)

    try:
        # Header
        start_time = datetime.now()
        print ''
        print_line('Starting NmapPy %.2f ( %s ) at %s' % (VERSION, WEB_URL, start_time.strftime('%Y-%m-%d %H:%M %Z%z')), args.output)

        targets_sorted = sorted(args.targets.keys(), key=lambda i: socket.inet_aton(i) if re.match('([0-9]{1,3}\.?){4}', i) is not None else '')
        for target in targets_sorted:
            ip = socket.gethostbyname(target)

            # HOST DISCOVERY
            ms = 0 # -1 = down; 0 = (forced) up; >0 = up with latency
            report_line = 'NmapPy scan report for %s%s' % (target, ' (%s)' % ip if ip != target else '')

            # Skip discovery if -Pn is set
            if not args.skip_host_discovery:
                ms = ping(ip, args.timing)

                # Host is down
                if ms == -1:
                    # If only one host is scanned, display info line
                    if len(args.targets) == 1:
                        print_line('Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn', args.output)

                    # Store info that host is down
                    args.targets[target] = (ip, ms, [])

                    # Continue to next host, which results a scan finished in case only one host is scanned
                    continue
                # Host is up
                else:
                    print_line(report_line, args.output)
            else:
                print_line(report_line, args.output)

            # Host status line
            latency = ''
            if not args.skip_host_discovery:
                latency = ' (%.2fs latency)' % (ms / 1000.0)
            print_line('Host is up%s.' % latency, args.output)

            # Skip port scan in case of ping scan
            if args.ping_scan:
                continue

            # PORT SCAN
            table = AsciiTable(args.ports)
            table.print_heading()
            results = []
            for port in args.ports:
                # Perform check and store result
                state = check_port(ip, args.proto, port, args.timing)
                results.append([port, state])

                # Show all if number of ports to check is less than or equal to MAX_RESULTS_DISPLAY
                if len(args.ports) <= MAX_RESULTS_DISPLAY or args.verbosity > 0 or state:
                    table.print_line(args.proto, port, state, args.output)

            args.targets[target] = (ip, ms, results)

            # Summary per host: Closed ports
            if len(args.ports) > MAX_RESULTS_DISPLAY:
                hidden = len(args.ports) - len(filter(lambda r: r[1], results))
                # All ports are closed
                if hidden == len(args.ports):
                    print_line('All %d scanned ports on %s are filtered' % (len(args.ports), ip), args.output)
                # Some ports are open
                elif hidden > 0:
                    print_line('Not shown: %d closed ports' % hidden, args.output)

            print_line('', args.output)

        # Overall summary
        end_time = datetime.now()
        elapsed = (end_time - start_time)
        targets_total = len(args.targets)
        targets_up = len(filter(lambda t: args.targets[t][1] != -1, args.targets))
        print_line(
            'NmapPy done: %d IP address%s (%d host%s up) scanned in %d.%02d seconds' % (
                targets_total,
                'es' if targets_total > 1 else '', # XX IP address(es)
                targets_up,
                's' if targets_up > 1 else '', # (XX host(s) up)
                elapsed.seconds,
                elapsed.microseconds/10000),
            args.output
        )

        # Round off scan
        finish_scan(args)

    except KeyboardInterrupt:
        sys.exit(1)


class AsciiTable:
    def __init__(self, ports=None):
        if not ports:
            self.maxportwidth = len('65535/tcp')
        else:
            self.maxportwidth = len('%d/tcp' % max(ports))

            


