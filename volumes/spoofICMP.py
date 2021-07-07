#!/usr/bin/python3
from scapy.all import *

ip = IP(src="10.1.0.1",dst="10.1.0.5")
icmp = ICMP()
pkt = ip/icmp
pkt.show()
send(pkt,verbose=0)
print("Send an ICMP packet")

