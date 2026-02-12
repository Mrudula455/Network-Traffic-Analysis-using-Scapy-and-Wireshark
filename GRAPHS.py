from scapy.all import rdpcap, TCP, UDP, ARP, ICMP
import matplotlib.pyplot as plt
from collections import defaultdict

# Load capture file
packets = rdpcap("Ex7.pcapng")

# Function to count packets per second
def packets_per_second(packet_list):
    time_count = defaultdict(int)
    for pkt in packet_list:
        sec = int(pkt.time)
        time_count[sec] += 1
    times = sorted(time_count.keys())
    counts = [time_count[t] for t in times]
    return times, counts

# 1️ All Packets
times, counts = packets_per_second(packets)
plt.figure()
plt.plot(times, counts)
plt.title("All Packets per Second")
plt.xlabel("Time (seconds)")
plt.ylabel("Number of Packets")
plt.show()

# 2️ TCP
tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]
times, counts = packets_per_second(tcp_packets)
plt.figure()
plt.plot(times, counts)
plt.title("TCP Packets per Second")
plt.xlabel("Time (seconds)")
plt.ylabel("Number of Packets")
plt.show()

# 3️ UDP
udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
times, counts = packets_per_second(udp_packets)
plt.figure()
plt.plot(times, counts)
plt.title("UDP Packets per Second")
plt.xlabel("Time (seconds)")
plt.ylabel("Number of Packets")
plt.show()

# 4️ ARP
arp_packets = [pkt for pkt in packets if pkt.haslayer(ARP)]
times, counts = packets_per_second(arp_packets)
plt.figure()
plt.plot(times, counts)
plt.title("ARP Packets per Second")
plt.xlabel("Time (seconds)")
plt.ylabel("Number of Packets")
plt.show()

# 5️ ICMP
icmp_packets = [pkt for pkt in packets if pkt.haslayer(ICMP)]
times, counts = packets_per_second(icmp_packets)
plt.figure()
plt.plot(times, counts)
plt.title("ICMP Packets per Second")
plt.xlabel("Time (seconds)")
plt.ylabel("Number of Packets")
plt.show()
