from scapy.all import *
from collections import defaultdict

packets = rdpcap("Ex7.pcapng")

conversation_data = defaultdict(lambda: {"bytes":0, "packets":0, "times":[]})

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        pair = tuple(sorted([src, dst]))

        conversation_data[pair]["bytes"] += len(pkt)
        conversation_data[pair]["packets"] += 1
        conversation_data[pair]["times"].append(pkt.time)

# Maximum bytes pair
max_pair = max(conversation_data.items(), key=lambda x: x[1]["bytes"])
print("Pair with maximum bytes:", max_pair[0])

# Average inter-packet time
for pair, data in conversation_data.items():
    times = sorted(data["times"])
    if len(times) > 1:
        diffs = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_time = sum(diffs)/len(diffs)
    else:
        avg_time = 0

    print("Pair:", pair)
    print("Total packets:", data["packets"])
    print("Average inter-packet time:", avg_time)
    print("Total bytes:", data["bytes"])
    print("------")
