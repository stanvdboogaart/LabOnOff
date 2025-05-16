from scapy.all import *;

# This is the file for ARP poisoning. I'm not sure if it works or how to test it :)

# First is my attempt at scanning the network. I'm not sure if this work and if this is what we wanted it to do if it does work.
# Scanning network for devices, ip is a range of ip adresses
def network_scan(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / arp
    # Note that sent is the ARP request I sent, received is the ARP reply, which has the IP and MAC information.
    packet_pairs = srp(packet, timeout=2, verbose=False)[0]
    hosts = []
    for sent, received in packet_pairs:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts


