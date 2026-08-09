#!/usr/bin/env python3

from scapy.all import Ether, Raw, sendp

import argparse
import time

INTERFACE = "h_1_1-eth0"
DEST_MAC = "01:0c:cd:01:00:00"
SRC_MAC = "00:00:00:00:00:01"
GOOSE_ETHERTYPE = 0x88B8

APP_ID = "0001"
GOCB_REF = "IED1/LLN0$GO$gcb01"
DATASET = "IED1/LLN0$Dataset01"
ST_NUM = 1
STATUS = "NORMAL"


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of GOOSE frames to send"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=0.01,
        help="Delay between frames in seconds"
    )

    args = parser.parse_args()

    if args.count <= 0:
        raise ValueError("Count must be greater than zero")

    if args.interval < 0:
        raise ValueError("Interval cannot be negative")

    print("Starting GOOSE sender")
    print(f"Frames: {args.count}")
    print(f"Interval: {args.interval} seconds")

    for sq_num in range(1, args.count + 1):

        # High-resolution monotonic timestamp used
        # for experimental latency measurement.
        send_time_ns = time.perf_counter_ns()

        # Retain a conventional timestamp as part
        # of the existing test payload.
        timestamp = time.time()

        payload = (
            f"app_id={APP_ID};"
            f"gocb_ref={GOCB_REF};"
            f"dataset={DATASET};"
            f"st_num={ST_NUM};"
            f"sq_num={sq_num};"
            f"timestamp={timestamp};"
            f"send_time_ns={send_time_ns};"
            f"status={STATUS}"
        )

        frame = (
            Ether(
                dst=DEST_MAC,
                src=SRC_MAC,
                type=GOOSE_ETHERTYPE
            )
            / Raw(load=payload.encode())
        )

        sendp(
            frame,
            iface=INTERFACE,
            verbose=False
        )

        if (
            sq_num == 1
            or sq_num == args.count
            or sq_num % 100 == 0
        ):
            print(
                f"Sent frame "
                f"sq_num={sq_num}"
            )

        if args.interval > 0:
            time.sleep(args.interval)

    print("Finished sending frames")


if __name__ == "__main__":
    main()
