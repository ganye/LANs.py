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
import time
import zlib
import shlex
import base64
import signal
import logging
import argparse
import threading
import subprocess
from StringIO import StringIO
# Quiet scapy's unnecessary logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

import nmap
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


    parser.add_argument('-i', '--interface', help='Choose the interface to'
            ' use.', dest='interface', required=True)
    
    parser.add_argument('-N', '--nbtscan', help='Enable nbtscan to get'
            ' Windows netbios names', action='store_true')
    parser.add_argument('-S', '--scan', help='Aggressively scans the target'
            ' for open port and background services. Logs output to'
            ' {victim_ip}.log', action='store_true')
    parser.add_argument('-V', '--victim', help='Specify the IP address of'
            ' the victim\'s machine')

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
        self.interface = interface
        self.addr = self._addr()
        self.gateway = self._gateway()
        self.netmask = self._netmask()
        self.cidr = self._cidr()

    def _addr(self):
        '''
        Returns the first IP address for the Network interface. If no address
        can be found, raises a WLANsError.
        '''
        addrs = netifaces.ifaddresses(self.interface)[netifaces.AF_INET]
        try:
            return addrs[0]['addr']
        except KeyError:
            raise WLANsError("could not find an ip address for '{iface}'"
                    .format(iface=self.interface))

    def _gateway(self):
        '''
        Returns the default gateway for the network interface. If no gateway
        can be found, raises a WLANsError.
        '''
        gateway = netifaces.gateways()['default'][netifaces.AF_INET]
        if self.interface in gateway:
            return gateway[0]
        raise WLANsError("could not find a default gateway for '{iface}'"
                .format(iface=self.interface))

    def _netmask(self):
        '''
        Returns the network mask for the network interface. If not network
        mask can be found, raises a WLANsError.
        '''
        addrs = netifaces.ifaddresses(self.interface)[netifaces.AF_INET]
        try:
            return addrs[0]['netmask']
        except KeyError:
            raise WLANsError("could not find a network mask for '{iface}'"
                    .format(iface=self.interface))

    def _cidr(self):
        '''
        Returns the network address in CIDR notation.
        '''
        addr = self.addr
        netmask = self.netmask

        binary_str = ''
        for octet in netmask.split('.'):
            binary_str += bin(int(octet))[2:].zfill(8)

        mask = str(len(binary_str.rstrip('0')))
        return '{addr}/{mask}'.format(addr=addr, mask=mask)

class active_users(object):
    users = []
    start_time = time.time()
    current_time = 0
    
    def __init__(self, network, options):
        self.network = network
        self.options = options

    def packet_callback(self, packet):
        if packet.hasLayer(scapy.Dot11):
            dot11packet = packet[scapy.Dot11]
            # This block is kind of cryptic -- basically, if the packet is a
            # Dot11 (Wireless) packet, check to see if any of the MAC addresses
            # present are in our list of users, and if so, increment their 
            # packet count by one. TODO: Rewrite this in a more straightforward
            # way
            if dot11packet.type == 2:
                addresses = [dot11packet.addr1.upper(),
                        dot11packet.addr2.upper(),
                        dot11packet.addr3.upper()]
                for address in addresses:
                    for user in self.users:
                        if address == user['mac']:
                            user['data'] += 1
                self.current_time = time.time()

            # Ensure that at least one second has passed since the user list
            # was last printed to the screen
            if self.current_time > self.start_time + 1:
                # First, sort users list by data packet count
                self.users.sort(key=lambda x: float(x['data']), reverse=True)
                
                os.system('clear')

                print('[*] {0}IP Address {1}and {2}data {1}sent/received'
                        .format(Color.tan, Color.white, Color.red))
                print('+------------------------------------+')
                for user in self.users:
                    ip = user['ip'].ljust(16)
                    data = str(user['data']).ljust(5)
                    out = '{0.tan}{1} {0.red}{2}{0.white}'.format(
                            Color, ip, data)
                    
                    if user.get('netbios'):
                        out += user['netbios']

                    print(out)

                print("\n[*] Hit Ctrl+C to stop and choose a victim IP")
                self.start_time = time.time()

    def find_users(self):
        self.arp_scan()
    
        if self.options.get('nbtscan'):
            self.nbt_scan()     

        monitor_iface = self.enable_monitor()

        try:
            scapy.sniff(iface=monitor_iface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            self.disable_monitor(monitor_iface)

        return raw_input('[*] Enter a non-router IP to target: ')

    def arp_scan(self):
        print('[*] Running ARP scan to identify users -- please wait...')
        user = {}
        scanner = nmap.PortScanner()
        found_router = False

        scan_result = scanner.scan(hosts=self.network.cidr, 
                arguments='-sn -n')['scan']

        # Only check hosts that responded to our arp
        filtered_hosts = filter(lambda x: scan_result[x]['status']['reason']
                == 'arp-response', scan_result.keys())

        for host in filtered_hosts: 
            user = {}
            user['ip'] = scan_result[host]['addresses']['ipv4']
            # python-nmap does not return a mac address for the current host
            # when running an arp scan
            user['mac'] = scan_result[host]['addresses'].get('mac', '')
            user['data'] = 0
            if not found_router and host == self.network.gateway:
                user['netbios'] = 'router'
                found_router = True
            else:
                user['netbios'] = ''
            
            self.users.append(user)

        if not found_router:
            print(self.network.gateway)
            sys.exit('[-] Router MAC not found -- exiting')

    def nbt_scan(self):
        try:
            cmd = 'nbtscan {cidr}'.format(cidr=self.network.cidr)
            nbt_process = subprocess.Popen(shlex.split(cmd),
                    stdout=subprocess.PIPE, stderr=open('dev/null'))
            output = nbt_process.communicate()[0]
            lines = output.splitlines()
            lines = lines[4:] # Lines 4..n contain the NetBIOS name
        except OSError:
            raise WLANsError("could not run nbtscan -- is it installed?")

        for line in lines:
            line = line.split()
            ip = like[0]
            nbtname = line[1]

            for user in self.users:
                if ip == user['ip']:
                    user['netbios'] = nbtname

    def enable_monitor(self):
        print('[*] Enabling monitor mode via airmon-ng')
        try:
            cmd = "airmon-ng start {0.interface}".format(self.network)
            airmon_process = subprocess.Popen(shlex.split(cmd),
                    stdout=subprocess.PIPE, stderr=open('/dev/null'))
            output = airmon_process.communicate()[0]
            # Use regex to parse the output of airmon-ng for the interface
            monitor_iface = re.search('monitor mode enabled on (.+)\)', output)
            
            return monitor_iface.group(1)
        except OSError:
            raise WLANsError("could not enable monitor mode -- is aircrack"
                    " installed?")

    def disable_monitor(self, iface):
        print('[*] Disabling monitor mode')
        os.syste('airmon-ng stop {iface} > /dev/ull 2>&1'.format(iface=iface))


class WLANs(object):
    def __init__(self, interface, options):
        self.network = Network(interface)

        # We want to convert options from an argparse.Namespace object to a
        # dict for ease of use -- __dict__ does just that for us
        self.options = options.__dict__

        self.victim = self.options.get('victim')
        if not self.victim:
            self.victim = active_users(self.network, self.options).find_users()




def main():
    # Check if the user is running as root -- if not, exit
    if not os.geteuid() == 0:
        sys.exit('Please run as root.')

    args = parse_args()

    interface = args.interface
    del args.interface

    scapy.conf.verb = 0
    scpay.conf.checkIPaddr = 0

    wlans = WLANs(interface, args)

if __name__ == '__main__':
    main()
