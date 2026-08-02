#!/usr/bin/env python3

from scapy.all import sniff, Ether, Raw
import csv
import os
import time
import hashlib

IN_IFACE = "h_2_1-eth0"
GOOSE_ETHERTYPE = 0x88B8
OUTPUT_FILE = "/home/student/goose-mininet/results/payload_validation.csv"
MAX_FRAMES = 5

received_count = 0

def parse_payload(payload_text):
    fields = {}
    for part in payload_text.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields

def validate_payload(fields):
    required_fields = [
        "app_id",
        "gocb_ref",
        "dataset",
        "st_num",
        "sq_num",
        "timestamp",
        "status"
    ]

    for field in required_fields:
        if field not in fields:
            return False

    if fields["app_id"] != "0001":
        return False

    if fields["status"] != "NORMAL":
        return False

    return True

def handle_packet(packet):
    global received_count

    if Ether in packet and packet[Ether].type == GOOSE_ETHERTYPE and Raw in packet:
        receive_time = time.time()
        payload_bytes = packet[Raw].load
        payload_text = payload_bytes.decode(errors="replace")

        fields = parse_payload(payload_text)
        validation_result = validate_payload(fields)

        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        row = {
            "received_count": received_count + 1,
            "sq_num": fields.get("sq_num", ""),
            "receive_time": receive_time,
            "validation_result": "PASS" if validation_result else "FAIL",
            "payload_hash": payload_hash,
            "payload_text": payload_text
        }

        file_exists = os.path.isfile(OUTPUT_FILE)

        with open(OUTPUT_FILE, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=row.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

        received_count += 1

        print(
            f"received frame {received_count}: "
            f"sq_num={row['sq_num']} "
            f"validation={row['validation_result']}"
        )

        if received_count >= MAX_FRAMES:
            raise KeyboardInterrupt

print("Payload validation started")
print(f"Listening on {IN_IFACE}")
print(f"Writing results to {OUTPUT_FILE}")

try:
    sniff(iface=IN_IFACE, prn=handle_packet, store=False)
except KeyboardInterrupt:
    print("Payload validation stopped")
