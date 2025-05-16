from scapy.all import *


while True: 
    pkt = sniff(count=1, filter="arp")
    print(pkt)