# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os

from scapy.all import *
from arp_ping import get_mac
# def show_dhcpoffer(pkt):

global _DEBUG    
_DEBUG = False

def pkt_callback(pkt):
    """
        dhcp message type:
            1 : dhcp discover
            2 : dhcp offer
            
            3 : request
            5 : request ?
            
            6 : nak
    """
    
    if _DEBUG: pkt.show() # debug statement

    if pkt.lastlayer().fields['options'][0][1] == 3:
        router_ip = pkt.fields.get('src')
        print ('DHCP REQUEST from %s' % router_ip)
    
    elif pkt.lastlayer().fields['options'][0][1] == 6:
        router_ip = pkt.lastlayer().fields['options'][1][1] 
        print ("DHCP NAK from: {} -> [{}]".format(router_ip, get_mac(router_ip, net_if)))
    
    elif pkt.lastlayer().fields['options'][0][1] == 2:
        router_ip = pkt.lastlayer().fields['options'][7][1] 
        print("DHCP OFFER from: {} [{}]".format(router_ip, get_mac(router_ip, net_if)))
    
def listen(iface, pfilter):
    # store argument must be set to 0 for the prn callback to be invoked
    sniff(iface=iface, filter=pfilter, prn=pkt_callback, store=0)

if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', required=True, 
                        help="interface to start listen to")

    parser.add_argument('-pfilter', required=False, default='port 68 and port 67',
                        help="filter")

    parser.add_argument('-debug', required=False, action="store_true", 
                        help="interface to start listen to")

    args = parser.parse_args()
    
    if args.debug: 
        _DEBUG = True
    print ("Start DHCP listener on interface '%s' with filter '%s'" % (args.i, args.pfilter))
    # run!
    
    global net_if 
    net_if = args.i
    
    listen(args.i,
           args.pfilter
          )
