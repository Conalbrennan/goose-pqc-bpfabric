#!/usr/bin/env python3

import argparse
import csv
import math
import os
import statistics


def percentile(values, p):
    """Calculate percentile using linear interpolation."""
    values = sorted(values)

    if len(values) == 1:
        return values[0]

    k = (len(values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)

    if f == c:
        return values[int(k)]

    return values[f] * (c - k) + values[c] * (k - f)


def main():
    parser = argparse.ArgumentParser(
        description="Calculate statistics for GOOSE latency experiment CSV files."
    )

    parser.add_argument("csv_file", help="Input latency CSV")
    parser.add_argument(
        "--sent",
        type=int,
        default=None,
        help="Number of packets transmitted, used to calculate packet loss"
    )

    args = parser.parse_args()

    latencies = []

    with open(args.csv_file, newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV contains no header")

        # Support both existing result formats.
        if "e2e_latency_ms" in reader.fieldnames:
            latency_column = "e2e_latency_ms"
        elif "latency_ms" in reader.fieldnames:
            latency_column = "latency_ms"
        else:
            raise ValueError(
                "Could not find e2e_latency_ms or latency_ms column"
            )

        for row in reader:

            # If validation information exists, only analyse PASS packets.
            if "validation_result" in row:
                if row["validation_result"].strip().upper() != "PASS":
                    continue

            try:
                value = float(row[latency_column])
                latencies.append(value)
            except (ValueError, TypeError):
                continue

    if not latencies:
        raise ValueError("No valid latency measurements found")

    n = len(latencies)

    mean = statistics.mean(latencies)
    median = statistics.median(latencies)

    if n > 1:
        sd = statistics.stdev(latencies)
    else:
        sd = 0.0

    minimum = min(latencies)
    maximum = max(latencies)

    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)

    if args.sent is not None:
        lost = max(args.sent - n, 0)
        packet_loss = (lost / args.sent) * 100 if args.sent > 0 else 0.0
    else:
        lost = None
        packet_loss = None

    print()
    print("GOOSE Experiment Statistics")
    print("---------------------------")
    print(f"File:        {args.csv_file}")
    print(f"n:           {n}")
    print(f"Mean:        {mean:.6f} ms")
    print(f"Median:      {median:.6f} ms")
    print(f"SD:          {sd:.6f} ms")
    print(f"Minimum:     {minimum:.6f} ms")
    print(f"Maximum:     {maximum:.6f} ms")
    print(f"P95:         {p95:.6f} ms")
    print(f"P99:         {p99:.6f} ms")

    if args.sent is not None:
        print(f"Sent:        {args.sent}")
        print(f"Received:    {n}")
        print(f"Lost:        {lost}")
        print(f"Packet loss: {packet_loss:.3f}%")
    else:
        print("Packet loss: not calculated (--sent not supplied)")

    # Write summary beside input CSV.
    base, _ = os.path.splitext(args.csv_file)
    output_file = base + "_statistics.csv"

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "source_file",
            "n",
            "mean_ms",
            "median_ms",
            "sd_ms",
            "min_ms",
            "max_ms",
            "p95_ms",
            "p99_ms",
            "sent",
            "received",
            "lost",
            "packet_loss_percent"
        ])

        writer.writerow([
            os.path.basename(args.csv_file),
            n,
            f"{mean:.6f}",
            f"{median:.6f}",
            f"{sd:.6f}",
            f"{minimum:.6f}",
            f"{maximum:.6f}",
            f"{p95:.6f}",
            f"{p99:.6f}",
            args.sent if args.sent is not None else "",
            n,
            lost if lost is not None else "",
            f"{packet_loss:.3f}" if packet_loss is not None else ""
        ])

    print()
    print(f"Statistics written to: {output_file}")


if __name__ == "__main__":
    main()
