import scapy.all as sc
import BasicDNSFunctions as DNS


DNS_ALREADY_FORWARDED = set()
DNS_RECORDS = {}
DNS_RECORDS["hlddrole.nl"] = "131.155.10.135"
outgoing_DNS_requests = {}
outstanding_queries = {}
MY_IP = sc.get_if_addr(sc.conf.iface)

def startServer():

    print(f"Starting fake DNS server")
    
    DNS.sniffResponses(handlePacket)




def handlePacket(packet):
        
        if not packet.haslayer(sc.DNS):
            return
        
        packet_ip = packet[sc.IP].src
        packet_sport = packet[sc.UDP].sport
        query_name = packet[sc.DNSQR].qname.decode()
        packet_id = packet[sc.DNS].id
        
        # incoming DNS request
        if packet.getlayer(sc.DNS).qr == 0:

            print(f"\n{(packet)[sc.DNS].summary()} recieved")
            # respond to the DNS query if it is already in record
            try:
                DNS.sendResponse(packet_ip, packet_sport, query_name, DNS_RECORDS[query_name])
                print(f"\n{query_name}: {(DNS_RECORDS[query_name])[sc.DNS].summary()} sent from DNS_RECORDS")

            except:
                print(f"\n{query_name} not stored yet")

            # if qname in DNS_ALREADY_FORWARDED:
            #     return

            try:
                outstanding_queries[query_name].append((packet_ip, packet_sport, packet_id, query_name))

            except:
                outstanding_queries[query_name] = [((packet_ip, packet_sport, packet_id, query_name))]


            # add this request to 
            outgoing_DNS_requests[query_name] = DNS.sendRequest(query_name)

            # response = send_DNS_Request(qname)
            # sc.send(response)
            # print(f"\nresponse sent: {qname}")

            # DNS_RECORDS[qname] = response
            # print(f"\nresponse added to DNS_RECORDS: {qname}, {packet[sc.DNS]}")
            # print(f"\n{response[sc.DNS]}")

            # DNS_ALREADY_FORWARDED.add(qname)
            # print(f"\n{qname} added to DNS_ALREADY_FORWARDED")


        # incoming DNS response
        elif packet.getlayer(sc.DNS).qr == 1:

            # check if incoming packet matches with a DNS request that the server sent
            try:
                (exp_id, exp_sport) = outgoing_DNS_requests[query_name]
                
            except:
                return
            
            # exit if packet is never requested
            if not (exp_id == packet_id and exp_sport == packet_sport):
                return
            DNS_RECORDS[query_name] = packet[sc.DNS].rdata
            while True:
                try:
                    (packet_ip, packet_sport, packet_id, query_name) = outstanding_queries[query_name].pop(0)
                    DNS.sendResponse(packet_ip, packet_sport, query_name, DNS_RECORDS[query_name])
                    
                except:
                    return


            
                
                

                

            
            qname = packet[sc.DNSQR].qname.decode()
            print(f"\n response recieved: {qname}")

            DNS_RECORDS[qname] = packet
            print(f"packet = {packet}")
            print(f"\nresponse added to DNS_RECORDS: {qname}")
            for i in range(packet[sc.DNS].ancount):
                print(f"\n{packet[sc.DNS].an[i].rdata}")
                

            

            DNS_ALREADY_FORWARDED.add(qname)
            print(f"\n{qname} added to DNS_ALREADY_FORWARDED")


        # with open("DNSrecords.txt", "w") as f:
        #     f.write(DNS_RECORDS)



if __name__ == "__main__":
    startServer()

