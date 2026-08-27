#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import base64
import csv
import fcntl
import json
import os
import struct
import time

TAP_IN = "tap_dec_in"
TAP_OUT = "tap_dec_out"

GOOSE_ETHERTYPE = 0x88B8

SESSION_FILE = (
    "/home/student/goose-mininet/keys/"
    "secure_kem/Server/active_session.json"
)

RESULTS_FILE = (
    "/home/student/goose-pqc-bpfabric/results/"
    "aes_decrypt_times.csv"
)

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

ETHERNET_HEADER_SIZE = 14
COUNTER_SIZE = 8
GCM_TAG_SIZE = 16

# Store measurements in memory during the experiment.
decryption_timings = []


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
                "decrypt_time_ns",
                "decrypt_time_us"
            ]
        )

        for (
            counter,
            decrypt_time_ns,
            decrypt_time_us
        ) in decryption_timings:

            writer.writerow(
                [
                    counter,
                    decrypt_time_ns,
                    decrypt_time_us
                ]
            )

    print(
        f"Decryption timing results saved to "
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

# Counter is marked as used only after
# successful authentication/decryption.
seen_counters = set()

tap_in_fd = open_tap(TAP_IN)
tap_out_fd = open_tap(TAP_OUT)

print("Decryption forwarder started")
print(
    f"Reading encrypted GOOSE frames from {TAP_IN}"
)
print(
    f"Writing decrypted GOOSE frames to {TAP_OUT}"
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

        # The encrypted body contains:
        #
        # 8-byte counter
        # +
        # AES-GCM ciphertext
        # +
        # 16-byte authentication tag
        encrypted_blob = (
            frame_data[ETHERNET_HEADER_SIZE:]
        )

        minimum_length = (
            COUNTER_SIZE
            + GCM_TAG_SIZE
            + 1
        )

        if len(encrypted_blob) < minimum_length:
            print(
                "Rejected encrypted frame: "
                "payload too short"
            )
            continue

        counter_bytes = (
            encrypted_blob[:COUNTER_SIZE]
        )

        encrypted_payload = (
            encrypted_blob[COUNTER_SIZE:]
        )

        packet_counter = int.from_bytes(
            counter_bytes,
            byteorder="big"
        )

        if packet_counter == 0:
            print(
                "Rejected encrypted frame: "
                "invalid packet counter"
            )
            continue

        if packet_counter in seen_counters:
            print(
                "Rejected replayed frame: "
                f"counter={packet_counter}"
            )
            continue

        nonce = (
            nonce_prefix
            + counter_bytes
        )

        try:

            # Measure ONLY AES-GCM decryption.
            decrypt_start_ns = time.perf_counter_ns()

            decrypted_payload = aesgcm.decrypt(
                nonce,
                encrypted_payload,
                aad
            )

            decrypt_end_ns = time.perf_counter_ns()

            decrypt_time_ns = (
                decrypt_end_ns
                - decrypt_start_ns
            )

            decrypt_time_us = (
                decrypt_time_ns / 1000.0
            )

        except InvalidTag:
            print(
                "Rejected encrypted frame: "
                "AES-GCM authentication failed"
            )
            continue

        except Exception as error:
            print(
                f"Decryption failed: {error}"
            )
            continue

        decryption_timings.append(
            (
                packet_counter,
                decrypt_time_ns,
                decrypt_time_us
            )
        )

        # Mark counter used only after
        # successful authentication.
        seen_counters.add(
            packet_counter
        )

        # Restore the original Ethernet frame directly.
        # No Scapy packet reconstruction is performed.
        decrypted_frame = (
            ethernet_header
            + decrypted_payload
        )

        os.write(
            tap_out_fd,
            decrypted_frame
        )

        # Limit terminal output during large tests.
        if (
            packet_counter <= 5
            or packet_counter % 100 == 0
        ):
            print(
                "Decrypted frame, "
                f"counter={packet_counter}, "
                f"AES_decrypt="
                f"{decrypt_time_ns} ns "
                f"({decrypt_time_us:.3f} us)"
            )

except KeyboardInterrupt:
    print(
        "\nDecryption forwarder stopped"
    )

finally:

    if decryption_timings:
        save_results()

    os.close(tap_in_fd)
    os.close(tap_out_fd)
