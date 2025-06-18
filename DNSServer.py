import scapy.all as sc

DNS_ALREADY_FORWARDED = set()
DNS_RECORDS = {}
MY_IP = sc.get_if_addr(sc.conf.iface)

def startServer():

    print("Starting fake DNS server")
    


    incoming_query = sc.sniff(filter="udp port 53", store=0, prn=dns_handle_packet)


    
def dns_handle_packet(packet):
        

        if packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 0:

            print("\n"+ (packet)[sc.DNS].summary() +  "recieved")
            
            qname = packet[sc.DNSQR].qname.decode()
            print("\npacket recieved: " + qname)

            try:
                sc.send(DNS_RECORDS[qname])
                print("\n" + qname (DNS_RECORDS[qname])[sc.DNS].summary() + " sent from DNS_RECORDS")

            except:
                print("\n" + qname + "not stored yet")


            if qname in DNS_ALREADY_FORWARDED:
                
                return

            

            response = send_DNS_Request(qname)
            sc.send(response)
            print("\nresponse sent: "+ {qname})

            DNS_RECORDS[qname] = response
            print("\nresponse added to DNS_RECORDS: " + {qname} + {packet[sc.DNS]})
            print("\n" + {response[sc.DNS]})

            DNS_ALREADY_FORWARDED.add(qname)
            print("\n" + {qname} + " added to DNS_ALREADY_FORWARDED")



        elif packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 1:
            
            qname = packet[sc.DNSQR].qname.decode()
            print("\n response recieved: " + {qname})

            DNS_RECORDS[qname] = packet
            print("packet = " + {packet})
            print("\nresponse added to DNS_RECORDS: " + {qname})
            for i in range(packet[sc.DNS].ancount):
                print("\n"+ {packet[sc.DNS].an[i].rdata})
                

            

            DNS_ALREADY_FORWARDED.add(qname)
            print("\n" + {qname} +  "added to DNS_ALREADY_FORWARDED")




            



    
    



def send_DNS_Request(domain):
    ans = sc.sr1(sc.IP(dst="8.8.8.8")/sc.UDP(sport=sc.RandShort(), dport=53)/sc.DNS(rd=1,qd=sc.DNSQR(qname=domain,qtype="A")))
    return ans
    
    
    
    
    
    


if __name__ == "__main__":
    startServer()

