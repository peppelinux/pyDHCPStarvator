#!/usr/bin/env python3
# Giuseppe De Marco

from scapy.all import *

def release_ip(src_mac,
               dst_mac,
               src_ip,
               dst_ip,
               timeout=0.2,
               debug=0):
    rand_xid=random.randint(1, 900000000)
    dhcp_release = Ether(src=src_mac,dst=dst_mac)\
                   /IP(src=src_ip,dst=dst_ip)\
                   /UDP(sport=68,dport=67)\
                   /BOOTP(ciaddr=src_ip,chaddr=[mac2str(src_mac)],xid=rand_xid,)\
                   /DHCP(options=[("message-type","release"),
                                  ("server_id",dst_ip),
                                  ("client_id", mac2str(src_mac)),
                                  "end"])
    sendp(dhcp_release)
    print("Requesting release for: %s (%s)" % (src_ip, src_mac))
    if debug: print('%r'%dhcp_release)
    time.sleep(timeout)

           
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-src_mac', required=True, 
                        help="source macaddr of the client of the requested ip to release")

    parser.add_argument('-src_ip', required=True, 
                        help="source ip addr of the client to release")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address, default: ff:ff:ff:ff:ff:ff")

    parser.add_argument('-dst_ip', required=True, 
                        help="DHCP server IP where releases have to been requested")

    parser.add_argument('-timeout', type=float, default=0.2, required=False, 
                        help="seconds to wait between a request and another. example -timeout 0.2")

    parser.add_argument('-debug', type=int, default=0,
                        help="print packets", required=False)

    args = parser.parse_args()
    
    # run!
    release_ip( args.src_mac,
                args.dst_mac,
                args.src_ip,
                args.dst_ip,
                args.timeout,
                args.debug)
    
