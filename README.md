# pyDHCPStarvator
scapy DHCP starvation

Scapy python program to exahust a DHCP pool.
This tool is not a purpose for doing network attacks but a strategy to exaust a DHCP Rogue pool when security-port and dhcp-snoop features are not available in the network equipments.

### Usage
````
usage: starvit.py [-h] -subnet SUBNET [-start N] [-end N]
                  [-server_id SERVER_ID]


sudo python starvit.py -subnet 192.168.27. -start 120 -end 150

# for specific attack just add a server_id
sudo python starvit.py -subnet 192.168.27. -start 120 -end 150 -server_id 192.168.27.254
````

#### -server_id
This option focus the attack on a specified endpoint, the DHCP server.
All the other DHCP server in the l2 broadcast will get something similar in their logs and will not release any ip from their pool.
````
Wed May 16 17:31:35 2018 daemon.info dnsmasq-dhcp[31796]: DHCPNAK(br-lan) 192.168.27.135 30:63:3a:33:38:3a wrong server-ID
````

## TODO

- better MAC randomization
- hostname randomization using a wordlist generator with laptop brandname and other popular things
- pleasae open an issue and suggest :)

#### License
Copyright (c) 2018 giuseppe.demarco@unical.it
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by the Università della Calabria, unical.it.
4. Neither the name of the Università della Calabria nor the
   names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY giuseppe.demarco@unical.it ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL giuseppe.demarco@unical.it BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
