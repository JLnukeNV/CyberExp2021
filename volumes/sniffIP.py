#!/usr/bin/env python3
from scapy.all import *

def print_pkt3(pkt):
    print("This is a packet in net 128.230.0.0/16")
    pkt.show()

pkt = sniff(iface='br-38222afe7e99',filter='net 128.230.0.0/16',prn=print_pkt3)
