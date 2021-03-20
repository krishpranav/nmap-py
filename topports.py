#!/usr/bin/env python
import sys
import csv

def read_services(namp_services_file):
    sfile = csv.reader(open(nmap_services_file, 'r'), dialect='excel-tab')
    services = []
    for s in sfile:
        if not str(s[0]).startswith('#'):
            services.append((s[1], s[0], s[2]))
    
    return sorted(services, key=lambda s: s[2], reverse=True)
