#!/usr/bin/python3
from scapy.all import *

pkt = IP(src="128.230.1.1",dst="10.9.0.1")
pkt2 = IP(src="10.9.0.5",dst="128.230.1.1")
pkt.show()
send(pkt,verbose=0)
print("Send an IP packet whose src IP is 128.230.1.1")

pkt2.show()
send(pkt2,verbose=0)
print("Send an IP packet whose dst IP is 128.230.1.1")
