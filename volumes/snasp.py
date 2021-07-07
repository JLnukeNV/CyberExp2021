#!/usr/bin/python3
from scapy.all import *

def spoof_reply(pkt):
    #eth2 = pkt[Ether]
    #eth = Ether()
    #eth.dst = eth2.dst   
    #eth.src = eth2.src
    #eth.type = eth2.type

    ip2 = pkt[IP]
    ip = IP()
    ip.chksum = 0
    ip.ihl = ip2.ihl
    ip.dst = ip2.src
    ip.src = ip2.dst

    icmp = ICMP()
    icmp.type = 0
    icmp.seq = pkt[ICMP].seq
    icmp.id = pkt[ICMP].id
    icmp.chksum = 0
    
    raw = pkt[Raw].load
    
    pkt2 = ip/icmp/raw
    del pkt2[IP].chksum
    del pkt2[ICMP].chksum
    pkt2.show2()
    send(pkt2)

pkt = sniff(iface='br-38222afe7e99',filter='icmp[icmptype] == icmp-echo',prn=spoof_reply)
