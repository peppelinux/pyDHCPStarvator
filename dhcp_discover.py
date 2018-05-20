#!/usr/bin/env python3
# Giuseppe De Marco

from scapy.all import *

def discover(dst_mac="ff:ff:ff:ff:ff:ff",
             ):
    myxid = random.randint(1, 900000000)
    src_mac = get_if_hwaddr(conf.iface)
    bogus_mac_address = RandMAC()
    options = [
                ("message-type", "discover"),
                ("param_req_list", chr(1),chr(121),chr(3),chr(6),chr(15),chr(119),chr(252),chr(95),chr(44),chr(46)),
                ("max_dhcp_size",1500),
                ("client_id", chr(1), mac2str(bogus_mac_address)),
                ("lease_time",10000),
                # ("hostname", hostname),
                ("end",'00000000000000')
            ]
    
    dhcp_discover = Ether(src=src_mac,dst=dst_mac)\
                    /IP(src="0.0.0.0",dst="255.255.255.255")\
                    /UDP(sport=68,dport=67)\
                    /BOOTP(chaddr=[mac2str(bogus_mac_address)],
                                   xid=myxid,
                                   flags=0xFFFFFF)\
                    /DHCP(options=options)
    
    sendp(dhcp_discover)
    #print('%r'%dhcp_discover)

            
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', required=True, 
                        help="local network interface")
    parser.add_argument('-pfilter', required=False, default='arp',
                        help="filter")
    args = parser.parse_args()
    conf.iface = args.i
    # run!
    discover()
