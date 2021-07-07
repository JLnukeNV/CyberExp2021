#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
   
pkt = sniff(iface='br-38222afe7e99',filter='icmp',prn=print_pkt)
