#!/usr/bin/python3
from scapy.all import *

ip = IP(src="10.9.0.5",dst="10.9.0.1")
tcp = TCP(sport=10002,dport=23)
pkt = ip/tcp
pkt.show()
send(pkt,verbose=0)
print("Send an TCP packet with src IP 10.9.0.5 and destination port 23")
