from scapy.all import *

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
    #print(pkt.summary())
    # print(pkt.lastlayer().fields['options'][0][1])
    if pkt.lastlayer().fields['options'][0][1] == 3:
        print ('DHCP REQUEST from %s' % pkt.fields.get('src'))
    if pkt.lastlayer().fields['options'][0][1] == 6:
        router_ip = pkt.lastlayer().fields['options'][1][1] 
        print ('DHCP NAK from %s' % router_ip)
    elif pkt.lastlayer().fields['options'][0][1] == 2:
        router_ip = pkt.lastlayer().fields['options'][7][1] 
        print ('DHCP OFFER from %s' % router_ip)

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
    listen(args.i,
           args.pfilter
          )
