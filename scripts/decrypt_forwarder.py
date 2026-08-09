#!/usr/bin/env python3

from scapy.all import Ether, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import base64
import fcntl
import json
import os
import struct

TAP_IN = "tap_dec_in"
TAP_OUT = "tap_dec_out"

GOOSE_ETHERTYPE = 0x88B8

SESSION_FILE = (
    "/home/student/goose-mininet/keys/"
    "secure_kem/Server/active_session.json"
)

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

COUNTER_SIZE = 8
GCM_TAG_SIZE = 16


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
        "Expected a 256-bit AES key"
    )

if len(nonce_prefix) != 4:
    raise RuntimeError(
        "Expected a 4-byte nonce prefix"
    )

aad = build_aad(session)

aesgcm = AESGCM(aes_key)

# Counters are added only after a frame has
# successfully authenticated and decrypted.
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

try:
    while True:

        frame_data = os.read(
            tap_in_fd,
            65535
        )

        packet = Ether(frame_data)

        if (
            packet.type == GOOSE_ETHERTYPE
            and Raw in packet
        ):

            encrypted_blob = bytes(
                packet[Raw].load
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
                decrypted_payload = aesgcm.decrypt(
                    nonce,
                    encrypted_payload,
                    aad
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

            # Only mark the counter as used once
            # authentication has succeeded.
            seen_counters.add(
                packet_counter
            )

            decrypted_frame = (
                Ether(
                    src=packet.src,
                    dst=packet.dst,
                    type=GOOSE_ETHERTYPE
                )
                / Raw(load=decrypted_payload)
            )

            os.write(
                tap_out_fd,
                bytes(decrypted_frame)
            )

            print(
                "Decrypted and forwarded frame, "
                f"counter={packet_counter}, "
                f"payload length="
                f"{len(decrypted_payload)} bytes"
            )

except KeyboardInterrupt:
    print(
        "\nDecryption forwarder stopped"
    )

finally:
    os.close(tap_in_fd)
    os.close(tap_out_fd)
