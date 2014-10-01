#! /usr/bin/env python2
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

    return parser.parse_args()

class WLANsError(Exception):
    '''
    Error class used by the application. Simply wraps the Exception class.
    '''
    pass

class Network(object):
    '''
    Simple network object used to store information about an interface's
    network. Contructor accepts the name of an interface, and then gathers
    the necessary information.
    '''
    def __init__(self, interface):
        self._iface = interace

    def addr(self):
        '''
        Returns the first IP address for the Network interface. If no address
        can be found, raises a WLANsError.
        '''
        addrs = netifaces.ifaddresses(self._iface)[netifaces.AF_INET]
        try:
            return addrs[0]['addr']
        except KeyError:
            raise WLANsError("could not find an ip address for '{iface}'"
                    .format(iface=self._iface))

    def gateway(self):
        '''
        Returns the default gateway for the network interface. If no gateway
        can be found, raises a WLANsError.
        '''
        gateways = netifaces.gateways()['default'][netifaces.AF_INET]
        for gateway in gateways:
            if self._iface in gateway:
                return gateway[0]
        raise WLANsError("could not find a default gateway for '{iface}'"
                .format(iface=self._iface))

    def netmask(self):
        '''
        Returns the network mask for the network interface. If not network
        mask can be found, raises a WLANsError.
        '''
        addrs = netifaces.ifaddresses(self._iface)[netifaces.AF_INET]
        try:
            return addrs[0]['netmask']
        except KeyError:
            raise WLANsError("could not find a network mask for '{iface}'"
                    .format(iface=self._iface))

    def cidr(self):
        addr = self.addr()
        netmask = self.netmask()

        binary_str = ''
        for octet in netmask.split('.'):
            binary_str += bin(int(octet))[2:].zfill(8)

        mask = str(len(binary_str.rstrip('0')))
        return '{addr}/{mask}'.format(addr=addr, mask=mask)

class WLANs(object):
    def __init__(self, interface, nmap=False, msbt=False):
        self.interface = interface

    def setup(self):
        self.gateway = get_default_gateway(iface)

def main():
    # Check if the user is running as root -- if not, exit
    if not os.geteuid() == 0:
        sys.exit('Please run as root.')

    args = parse_args()

    wlans = WLANs(interface=args.interface)

if __name__ == '__main__':
    main()
