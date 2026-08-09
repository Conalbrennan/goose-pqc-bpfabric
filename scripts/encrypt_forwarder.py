#!/usr/bin/env python3

from scapy.all import Ether, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64
import fcntl
import json
import os
import struct

TAP_IN = "tap_enc_in"
TAP_OUT = "tap_enc_out"

GOOSE_ETHERTYPE = 0x88B8

SESSION_FILE = (
    "/home/student/goose-mininet/keys/"
    "secure_kem/client/active_session.json"
)

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

COUNTER_SIZE = 8
MAX_COUNTER = (1 << 64) - 1

# Temporary security test:
# resend the first valid encrypted frame once.
REPLAY_TEST = True


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

packet_counter = 0
replay_sent = False

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
print("Replay security test enabled")

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

            original_payload = bytes(
                packet[Raw].load
            )

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

            encrypted_payload = aesgcm.encrypt(
                nonce,
                original_payload,
                aad
            )

            new_payload = (
                counter_bytes
                + encrypted_payload
            )

            encrypted_frame = (
                Ether(
                    src=packet.src,
                    dst=packet.dst,
                    type=GOOSE_ETHERTYPE
                )
                / Raw(load=new_payload)
            )

            os.write(
                tap_out_fd,
                bytes(encrypted_frame)
            )

            print(
                "Encrypted and forwarded frame, "
                f"counter={packet_counter}, "
                f"encrypted length="
                f"{len(new_payload)} bytes"
            )

            # Replay attack simulation:
            # retransmit the exact first protected frame.
            if (
                REPLAY_TEST
                and packet_counter == 1
                and not replay_sent
            ):
                os.write(
                    tap_out_fd,
                    bytes(encrypted_frame)
                )

                replay_sent = True

                print(
                    "Replay test: resent encrypted frame, "
                    "counter=1"
                )

except KeyboardInterrupt:
    print(
        "\nEncryption forwarder stopped"
    )

finally:
    os.close(tap_in_fd)
    os.close(tap_out_fd)        IFF_TAP | IFF_NO_PI
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

            original_payload = bytes(
                packet[Raw].load
            )

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

            # 4-byte session nonce prefix
            # + 8-byte packet counter
            # = 12-byte AES-GCM nonce
            nonce = (
                nonce_prefix
                + counter_bytes
            )

            encrypted_payload = aesgcm.encrypt(
                nonce,
                original_payload,
                aad
            )

            # Counter is transmitted.
            # Nonce is reconstructed by receiver
            # using its session nonce prefix.
            new_payload = (
                counter_bytes
                + encrypted_payload
            )

            encrypted_frame = (
                Ether(
                    src=packet.src,
                    dst=packet.dst,
                    type=GOOSE_ETHERTYPE
                )
                / Raw(load=new_payload)
            )

            os.write(
                tap_out_fd,
                bytes(encrypted_frame)
            )

            print(
                "Encrypted and forwarded frame, "
                f"counter={packet_counter}, "
                f"encrypted length="
                f"{len(new_payload)} bytes"
            )

except KeyboardInterrupt:
    print(
        "\nEncryption forwarder stopped"
    )

finally:
    os.close(tap_in_fd)
    os.close(tap_out_fd)
