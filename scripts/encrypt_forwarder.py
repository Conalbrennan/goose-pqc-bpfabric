#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64
import csv
import fcntl
import json
import os
import struct
import time

TAP_IN = "tap_enc_in"
TAP_OUT = "tap_enc_out"

GOOSE_ETHERTYPE = 0x88B8

SESSION_FILE = (
    "/home/student/goose-mininet/keys/"
    "secure_kem/client/active_session.json"
)

RESULTS_FILE = (
    "/home/student/goose-pqc-bpfabric/results/"
    "aes_encrypt_times.csv"
)

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

ETHERNET_HEADER_SIZE = 14
COUNTER_SIZE = 8
MAX_COUNTER = (1 << 64) - 1

# Store measurements in memory during the experiment.
encryption_timings = []


def open_tap(interface_name):

    tap_fd = os.open("/dev/net/tun", os.O_RDWR)

    interface_request = struct.pack(
        "16sH",
        interface_name.encode("utf-8"),
        IFF_TAP | IFF_NO_PI
    )

    fcntl.ioctl(
        tap_fd,
        TUNSETIFF,
        interface_request
    )

    return tap_fd


def get_ethertype(frame_data):

    if len(frame_data) < ETHERNET_HEADER_SIZE:
        return None

    return struct.unpack(
        "!H",
        frame_data[12:14]
    )[0]


def build_aad(session):

    required_fields = (
        "group_id",
        "key_id",
        "key_version",
    )

    for field in required_fields:
        if field not in session:
            raise RuntimeError(
                f"Session file missing required field: {field}"
            )

    aad_data = {
        "group_id": session["group_id"],
        "key_id": session["key_id"],
        "key_version": session["key_version"],
    }

    return json.dumps(
        aad_data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def save_results():

    os.makedirs(
        os.path.dirname(RESULTS_FILE),
        exist_ok=True
    )

    with open(
        RESULTS_FILE,
        "w",
        newline=""
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow(
            [
                "packet_counter",
                "encrypt_time_ns",
                "encrypt_time_us"
            ]
        )

        for (
            counter,
            encrypt_time_ns,
            encrypt_time_us
        ) in encryption_timings:

            writer.writerow(
                [
                    counter,
                    encrypt_time_ns,
                    encrypt_time_us
                ]
            )

    print(
        f"Encryption timing results saved to "
        f"{RESULTS_FILE}"
    )


with open(SESSION_FILE, "r") as session_file:
    session = json.load(session_file)

if session.get("status") != "ACTIVE":
    raise RuntimeError(
        "No active authenticated KEM session"
    )

aes_key = base64.b64decode(
    session["aes_key_b64"]
)

nonce_prefix = base64.b64decode(
    session["nonce_prefix_b64"]
)

if len(aes_key) != 32:
    raise RuntimeError(
        "Expected a 192-bit AES key"
    )

if len(nonce_prefix) != 4:
    raise RuntimeError(
        "Expected a 4-byte nonce prefix"
    )

aad = build_aad(session)

aesgcm = AESGCM(aes_key)

packet_counter = 0

tap_in_fd = open_tap(TAP_IN)
tap_out_fd = open_tap(TAP_OUT)

print("Encryption forwarder started")
print(
    f"Reading original GOOSE frames from {TAP_IN}"
)
print(
    f"Writing encrypted GOOSE frames to {TAP_OUT}"
)
print(
    f"GOOSE group: {session['group_id']}"
)
print(
    f"Key ID: {session['key_id']}"
)
print(
    f"Key version: {session['key_version']}"
)
print(
    f"Timing results will be saved to "
    f"{RESULTS_FILE}"
)
print(
    "Raw-byte forwarding enabled "
    "(Scapy removed from packet path)"
)

try:
    while True:

        frame_data = os.read(
            tap_in_fd,
            65535
        )

        # Ignore malformed Ethernet frames.
        if len(frame_data) < ETHERNET_HEADER_SIZE:
            continue

        ethertype = get_ethertype(frame_data)

        if ethertype != GOOSE_ETHERTYPE:
            continue

        # Preserve the original Ethernet header exactly.
        ethernet_header = (
            frame_data[:ETHERNET_HEADER_SIZE]
        )

        # Everything after the Ethernet header is
        # the original GOOSE payload.
        original_payload = (
            frame_data[ETHERNET_HEADER_SIZE:]
        )

        if not original_payload:
            continue

        if packet_counter >= MAX_COUNTER:
            raise RuntimeError(
                "Packet counter exhausted; "
                "rekey required"
            )

        packet_counter += 1

        counter_bytes = packet_counter.to_bytes(
            COUNTER_SIZE,
            byteorder="big"
        )

        nonce = (
            nonce_prefix
            + counter_bytes
        )

        # Measure ONLY AES-GCM encryption.
        encrypt_start_ns = time.perf_counter_ns()

        encrypted_payload = aesgcm.encrypt(
            nonce,
            original_payload,
            aad
        )

        encrypt_end_ns = time.perf_counter_ns()

        encrypt_time_ns = (
            encrypt_end_ns
            - encrypt_start_ns
        )

        encrypt_time_us = (
            encrypt_time_ns / 1000.0
        )

        encryption_timings.append(
            (
                packet_counter,
                encrypt_time_ns,
                encrypt_time_us
            )
        )

        # Construct the outgoing frame directly
        # from raw bytes. No Scapy packet object
        # is created or serialised.
        encrypted_frame = (
            ethernet_header
            + counter_bytes
            + encrypted_payload
        )

        os.write(
            tap_out_fd,
            encrypted_frame
        )

        # Limit terminal output during large tests.
        if (
            packet_counter <= 5
            or packet_counter % 100 == 0
        ):
            print(
                "Encrypted frame, "
                f"counter={packet_counter}, "
                f"AES_encrypt="
                f"{encrypt_time_ns} ns "
                f"({encrypt_time_us:.3f} us)"
            )

except KeyboardInterrupt:
    print(
        "\nEncryption forwarder stopped"
    )

finally:

    if encryption_timings:
        save_results()

    os.close(tap_in_fd)
    os.close(tap_out_fd)
