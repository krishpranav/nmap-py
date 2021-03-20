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


