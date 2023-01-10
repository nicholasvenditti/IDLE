import scapy
from scapy.all import *

dst = str(input("Please enter the IPv4 address of a remote networked device: "))

os = "Linux"
pkt = IP(dst = dst)/ICMP()
p, q = srloop(pkt, verbose = 0, count = 5)

# Function that receives a list of id values and returns the likely id counter type
def type_of_counter(id_values):

    zero = True
    incremental = True

    for i in range(0, len(id_values) - 1):

        for j in range(i + 1, len(id_values)):

            if id_values[i] == id_values[j]:
                zero = zero and True
                incremental = False
            elif id_values[i] < id_values[j]:
                incremental = incremental and True
                zero = False
            else:
                zero = False
                incremental = False

    if zero:
        return "zero"
    elif incremental:
        return "incremental"
    else:
        return "random"

if bool(p):
    
    print("Device with this IP address responds to ICMP-ping requests pkts: yes")

    if p[0].answer.ttl > 64:
        os = "Windows"

    icmp_id_values = []
    for couple in p:
        icmp_id_values.append(couple.answer.id)

    print("IP-ID counter observed in ICMP-reply pkts: " + type_of_counter(icmp_id_values))

else:
    print("Device with this IP address responds to ICMP-ping requests pkts: no")

pkt = IP(dst = dst)/TCP(dport = 80, flags = "S")
p, q = srloop(pkt, verbose = 0, count = 1)

if bool(p) and p[0].answer.payload.flags == "SA":

    pkts = sniff(filter = "tcp and src host " + dst + " and src port 80", timeout = 120)

    if bool(pkts):

        intervals = [str(round(pkts[0].time - p[0].answer.time)) + "s"]
        for i in range(1, len(pkts)):
            intervals.append(str(round(pkts[i].time - pkts[i - 1].time)) + "s")

    pkt = IP(dst = dst)/TCP(dport = 80, flags = "S")
    p, q = srloop(pkt, verbose = 0, count = 5)

    print("TCP port 80 on this device is open: yes")

    tcp_id_values = []
    for couple in p:
        tcp_id_values.append(couple.answer.id)
    
    print("IP-ID counter observed in TCP replies: " + type_of_counter(tcp_id_values))

    if bool(pkts):
        print("SYN cookies deployed by service running on TCP port 80: no")
        print("max # of SYN-ACK pkts retransmitted by service on TCP port 80: " + str(len(pkts)))
        print("observed SYN-ACK retransmission interval(s): " + ", ".join(intervals))     
    else:
        print("SYN cookies deployed by service running on TCP port 80: yes")

else:
    print("TCP port 80 on this device is open: no")

print("Likely OS system deployed on this device: " + os)
