from scapy.all import rdpcap

packets = rdpcap("Ex7.pcapng")

total_packets = len(packets)
total_size = sum(len(pkt) for pkt in packets)

header_size = 0
for pkt in packets:
    if pkt.haslayer("IP"):
        header_size += pkt["IP"].ihl * 4

print("Total number of packets:", total_packets)
print("Total size of data (bytes):", total_size)
print("Total header size (bytes):", header_size)
