#!/usr/bin/env python3

from scapy.all import sniff, Ether, Raw

import argparse
import csv
import hashlib
import os
import time

IN_IFACE = "h_2_1-eth0"
GOOSE_ETHERTYPE = 0x88B8

DEFAULT_OUTPUT_FILE = (
    "/home/student/goose-pqc-bpfabric/"
    "results/latency_results.csv"
)

received_count = 0
target_count = 0
output_file = ""


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
        "send_time_ns",
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

    if not (
        Ether in packet
        and packet[Ether].type == GOOSE_ETHERTYPE
        and Raw in packet
    ):
        return

    receive_time_ns = time.perf_counter_ns()

    payload_bytes = bytes(
        packet[Raw].load
    )

    payload_text = payload_bytes.decode(
        errors="replace"
    )

    fields = parse_payload(
        payload_text
    )

    validation_result = validate_payload(
        fields
    )

    latency_ms = ""

    if "send_time_ns" in fields:
        try:
            send_time_ns = int(
                fields["send_time_ns"]
            )

            latency_ns = (
                receive_time_ns
                - send_time_ns
            )

            latency_ms = (
                latency_ns / 1_000_000
            )

        except ValueError:
            send_time_ns = ""
    else:
        send_time_ns = ""

    payload_hash = hashlib.sha256(
        payload_bytes
    ).hexdigest()

    received_count += 1

    row = {
        "received_count": received_count,
        "sq_num": fields.get(
            "sq_num",
            ""
        ),
        "send_time_ns": send_time_ns,
        "receive_time_ns": receive_time_ns,
        "latency_ms": (
            f"{latency_ms:.6f}"
            if latency_ms != ""
            else ""
        ),
        "validation_result": (
            "PASS"
            if validation_result
            else "FAIL"
        ),
        "payload_hash": payload_hash
    }

    with open(
        output_file,
        "a",
        newline=""
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=row.keys()
        )

        writer.writerow(row)

    if (
        received_count == 1
        or received_count == target_count
        or received_count % 100 == 0
    ):

        print(
            f"Received frame {received_count}: "
            f"sq_num={row['sq_num']} "
            f"latency={row['latency_ms']} ms "
            f"validation="
            f"{row['validation_result']}"
        )

    if received_count >= target_count:
        raise KeyboardInterrupt


def main():

    global target_count
    global output_file

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of GOOSE frames to record"
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help="CSV output filename"
    )

    args = parser.parse_args()

    if args.count <= 0:
        raise ValueError(
            "Count must be greater than zero"
        )

    target_count = args.count
    output_file = args.output

    output_directory = os.path.dirname(
        output_file
    )

    os.makedirs(
        output_directory,
        exist_ok=True
    )

    # Each experimental run starts with
    # a fresh results file.
    if os.path.exists(output_file):
        os.remove(output_file)

    fieldnames = [
        "received_count",
        "sq_num",
        "send_time_ns",
        "receive_time_ns",
        "latency_ms",
        "validation_result",
        "payload_hash"
    ]

    with open(
        output_file,
        "w",
        newline=""
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

    print("Payload validation and latency measurement started")
    print(f"Listening on {IN_IFACE}")
    print(f"Target frames: {target_count}")
    print(f"Writing results to: {output_file}")

    try:

        sniff(
            iface=IN_IFACE,
            prn=handle_packet,
            store=False
        )

    except KeyboardInterrupt:

        print(
            "Payload validation stopped"
        )

        print(
            f"Frames recorded: "
            f"{received_count}"
        )

        print(
            f"Results saved to: "
            f"{output_file}"
        )


if __name__ == "__main__":
    main()
