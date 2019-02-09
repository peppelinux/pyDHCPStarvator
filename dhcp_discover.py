#!/usr/bin/env python3
# Giuseppe De Marco

# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def dhcp_discover(dst_mac="ff:ff:ff:ff:ff:ff", debug=False):
    myxid = random.randint(1, 900000000)
    src_mac = get_if_hwaddr(conf.iface)
    bogus_mac_address = RandMAC()
    options = [("message-type", "discover"),
               #("param_req_list", chr(1),chr(121),chr(3),chr(6),chr(15),chr(119),chr(252),chr(95),chr(44),chr(46)),
               ("max_dhcp_size",1500),
               ("client_id", mac2str(bogus_mac_address)),
               ("lease_time",10000),
               # ("hostname", hostname),
               ("end",bytes('00000000000000', encoding='ascii'))]
    dhcp_request = Ether(src=src_mac,dst=dst_mac)\
                    /IP(src="0.0.0.0",dst="255.255.255.255")\
                    /UDP(sport=68,dport=67)\
                    /BOOTP(chaddr=[mac2str(bogus_mac_address)],
                                   xid=myxid,
                                   flags=0xFFFFFF)\
                    /DHCP(options=options)
    sendp(dhcp_request,
          iface=conf.iface)
            
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', required=True, 
                        help="local network interface")
    parser.add_argument('-debug', required=False, action="store_true", 
                        help="interface to start listen to")
    args = parser.parse_args()
    conf.iface = args.i
    # run!
    dhcp_discover(dst_mac="ff:ff:ff:ff:ff:ff",
                  debug=args.debug)
