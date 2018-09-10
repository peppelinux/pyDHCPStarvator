# pyDHCPStarvator

This is a Scapy python program that can run out an entire DHCP pool.
This tool was not created for doing network attacks but like a strategy to exaust a DHCP Rogue pool when security-port and dhcp-snoop features are not available in your network equipments.

### Requirements
````
# python2
apt install python2-pip python-dev
pip install scapy

# python3
apt install python3-dev python3-pip
pip3 install scapy-python3
````

### Usage
````
usage: starvit.py [-h] -subnet SUBNET [-start N] [-end N]
                  [-server_id SERVER_ID] [-random_hostnames]
                  [-dst_mac DST_MAC] [-timeout TIMEOUT] [-debug]


sudo python starvit.py -subnet 192.168.27. -start 120 -end 150

# just add a server_id as a specific target
sudo python starvit.py -subnet 192.168.27. -start 10 -end 253 -server_id 192.168.27.254

# specify server by its MAC address and print packets to stdout
python starvit.py -subnet 192.168.1. -start 80 -end 100 -dst_mac 08:00:27:7C:F9:41 -debug


````

#### example stdout with -debug option
````
Requesting: 192.168.1.98
<Ether  dst=08:00:27:7C:F9:41 src=7b:7b:d1:5a:6b:62 type=IPv4 |<IP  frag=0 proto=udp src=0.0.0.0 dst=255.255.255.255 |<UDP  sport=bootpc dport=bootps |<BOOTP  chaddr=<RandMAC> options='c\x82Sc' |<DHCP  options=[message-type='request' requested_addr=192.168.1.98 end] |>>>>>
.
Sent 1 packets.
````

#### -server_id and -dst_mac
These options focus the attack on a specified endpoint, the DHCP server, by ip or mac address.

If you using a wrong server_id value all the DHCP servers in the l2 broadcast will get something similar in their logs and will not release any ip from their pool.
````
Wed May 16 17:31:35 2018 daemon.info dnsmasq-dhcp[31796]: DHCPNAK(br-lan) 192.168.27.135 30:63:3a:33:38:3a wrong server-ID
````

### Request an IP release
Usefull if you want to force a DHCP server to remove a DHCP lease and then make a client to request an ip again
````
python release_ip.py -src_mac 66:36:3a:37:31:3a -src_ip 192.168.1.93 -dst_mac 08:00:27:7C:F9:41 -dst_ip 192.168.1.1 -debug 1

````

### Send a DHCP discover and listen for event
A listener could be also executed to run a function callback for every packet sniffed.
For example we could send a gratuitous DHCP DISCOVER to sniff DHCP OFFER from rogue DHCP servers, then run a starvation over them.

````
# DHCP DISCOVER
python2 dhcp_discover.py -i eth2

# DHCP event listener
python listener.py -i eth2 [-debug]

Start DHCP listener on interface 'eth2' with filter 'port 68 and port 67'
DHCP OFFER from: 10.21.0.254 [d4:ca:6d:e6:6a:d7]
DHCP OFFER from: 192.168.1.1 [08:00:27:7c:f9:41]
DHCP OFFER from: 192.168.1.1 [08:00:27:7c:f9:41]
````

### Results
![example](images/example.png)
An OpenWRT DHCP server used as victim.
Some fake client requests was forged with "-random_hostnames" option, some other not.

![discover](images/discover2.png)
Server side effects of DHCP Discovery, dhcp_discover.py will always use a fake mac address to run its inspections.

### Hints
````
# tcpdump activity sniffing
tcpdump -i $ifname -n 'port 67 and port 68'

# dhcp discover
nmap --script broadcast-dhcp-discover -e eth0
````
### License

DHCPStarvator is made by Giuseppe De Marco and it's released under the GPL 3 license.

### Todo

- confiurable MAC randomization (arguments);
- background sniffer that intercept unauthoritative rogue's DHCP NAK and start starvation of source DHCP endpoint
- background unsolicitated DHCP requests, ignore authoritative DHCP and starve all the other DHCPs
- DHCP Server whitelist (do not starvate them)
- please open an issue and suggest :)

### Resources

- http://scapy.readthedocs.io/en/latest/#sniffing
- https://phaethon.github.io/scapy/api/
- https://blog.jasonantman.com/2010/04/dhcp-debugging-and-handy-tcpdump-filters/
- https://www.whitewinterwolf.com/posts/2017/10/30/dhcp-exploitation-guide/
- https://github.com/foreni-packages/dhcpig

### Special thanks
To [Daniele Albrizio](https://github.com/speedj) for given a name to an idea ;)
