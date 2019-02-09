#!/usr/bin/env python3

# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import argparse
from scapy.all import *

bcast_mac = 'ff:ff:ff:ff:ff:ff'

def get_mac(ip_addr, interface):
    # arp_packet creation
    interface_mac = get_if_hwaddr(interface)
    eth_hdr = Ether(src=interface_mac, dst=bcast_mac, type=0x0806) # Ethernet header (Broadcast ethernet)
    arp_hdr = ARP(op=ARP.who_has, pdst=ip_addr) # ARP header with 'who has this IP with MAC?'
    padstr = '\x00' * (60 - len(eth_hdr) - len(arp_hdr))
    pad = Padding(load=padstr) # a bunch of 0-bytes
    arp_packet = eth_hdr/arp_hdr/pad
    # Send ARP packets 5 times until it get correct response
    for i in range(5):
        response = srp1(arp_packet, iface=interface, verbose=0, timeout=5)
        if response == None:
            print("ARP faild. retransmitting", file=sys.stderr)
            continue
        else:
            break

    if response.op == 2:
        return response.hwsrc
    else:
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str,
                        help='IP of the host you want to arp ping')
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    args = parser.parse_args()
    fetched_mac = get_mac(args.ip, args.interface)
    if fetched_mac: print("{} = {}".format(args.ip, fetched_mac ))
