import scapy.all as sc
import time


def send_DNS_Request(domain):
    ans = sc.sr1(sc.IP(dst="8.8.8.8")/sc.UDP(sport=sc.RandShort(), dport=53)/sc.DNS(rd=1,qd=sc.DNSQR(qname=domain,qtype="A")))
    print(ans[sc.DNS].summary())
    return ans


if __name__ == "__main__":
    send_DNS_Request("test.com")
    time.sleep(20)

