#!/usr/bin/python3
from scapy.all import *

ip = IP()
ip.dst = sys.argv[1]
ip.ttl = 1
protocol = ICMP()

print("Traceroute " + str(ip.dst) + " for no more than 30 jumps")
while ip.ttl <= 30:
    send_time = time.time()
    pkt = ip / protocol
    re = sr1(pkt, timeout=1, verbose=False)
    re_time = time.time()
    if not re:
        print("No." + str(ip.ttl) + " router IP missing, ICMP ignored")
    else:
        print("No." + str(ip.ttl) + " router IP :" + re.getlayer(IP).src + ", costs " + str(1000*(re_time - send_time)) + "ms")
        if re.getlayer(ICMP).type != 11 or re.getlayer(ICMP).code != 0:
            print(str(ip.ttl) + " jumps in all")
            break   
    ip.ttl += 1
