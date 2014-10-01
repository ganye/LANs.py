#! /usr/bin/env python2

__author__ = 'ganye'
__license__ = 'BSD'
__contact__ = 'github.com/ganye'
__version__ = 0.1

import os
import sys
import gzip
import zlib
import base64
import signal
import logging
import argparse
import threading
from StringIO import StringIO
# Quiet scapy's unnecessary logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

import scapy
import netifaces
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.interfaces import IReadDescriptor
from netfilterqueue import NetfilterQueue

from color import Color

def parse_args():
    '''
    Setup CLI arguments.
    '''
    parser = argparse.ArgumentParser()

    parser.add_argument('-S', '--scan', help='Aggressively scans the target'
            ' for open port and background services. Logs output to'
            ' {victim_ip}.log', action='store_true')
    parser.add_argument('-N', '--nbtscan', help='Enable nbtscan to get'
            ' Windows netbios names', action='store_true')
    parser.add_argument('-i', '--interface', help='Choose the interface to'
            ' use.', dest='interface', required=True)

def get_default_gateway(iface):
    gws = netifaces.gateways()['default']
    gws = gws[netifaces.AF_INET] # Get IPv4 GW

    for gw in gws:
        if iface in gw:
            return gw[0]
    raise WLANsError("could not find a gateway for '{iface}'".format(
        iface=iface))

class WLANs(object):
    '''
    Description: ARP poisons a LAN victim over wifi and print any interesting
        information, such as usernames/passwords and messages. Based on
        DanMcInerney's LANs.py (https://github.com/DanMcInerney/LANs.py).
    Prerequisites:
        - Linux
        - nmap (optional -- needed for -S/--scan flag)
        - nbtscan (optional -- needed for -N/--netbios flag)
        - aircrack-ng
        - Python 2.x
        - nfqueue-bindings
        - Scapy
        - Twisted
        - iptables
        - python-iptables
        - netifaces
    '''
    def __init__(self, interface, nmap=False, msbt=False):
        self.interface = interface
        self.gateway = get_default_gateway(iface)

def main():
    # Check if the user is running as root -- if not, exit
    if not os.geteuid() == 0:
        sys.exit('Please run as root.')

    args = parse_args()

    wlans = WLANs(interface=args.interface)

if __name__ == '__main__':
    main()
