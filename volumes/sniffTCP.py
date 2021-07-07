#!/usr/bin/env python3
from scapy.all import *

def print_pkt2(pkt):
    print("This is a TCP packet from 10.9.0.5 whose destination port is 23")
    pkt.show()

pkt = sniff(iface='br-38222afe7e99',filter='tcp and src host 10.9.0.5 and dst port 23',prn=print_pkt2)
