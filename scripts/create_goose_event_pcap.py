#!/usr/bin/env python3

from scapy.all import rdpcap, wrpcap

INPUT = "/home/student/goose-pqc-bpfabric/results/goose_event/goose_event_base.pcap"
OUTPUT = "/home/student/goose-pqc-bpfabric/results/goose_event/goose_event_sequence.pcap"

EVENT_TIMES = [
    0.000,
    0.001,
    0.002,
    0.004,
    0.008,
    0.016,
    0.032,
    0.064,
    0.128,
    0.256,
]

packets = rdpcap(INPUT)

if len(packets) != len(EVENT_TIMES):
    raise ValueError(
        f"Expected {len(EVENT_TIMES)} packets, found {len(packets)}"
    )

base_time = float(packets[0].time)

for packet, offset in zip(packets, EVENT_TIMES):
    packet.time = base_time + offset

wrpcap(OUTPUT, packets)

print(f"Created: {OUTPUT}")
print(f"Packets: {len(packets)}")
print("Event times (ms):")
for index, offset in enumerate(EVENT_TIMES, start=1):
    print(f"{index}: {offset * 1000:.3f}")
