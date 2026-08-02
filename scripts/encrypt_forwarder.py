#!/usr/bin/env python3

from scapy.all import Ether, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import json
import base64
import fcntl
import os
import struct

TAP_IN = "tap_enc_in"
TAP_OUT = "tap_enc_out"

GOOSE_ETHERTYPE = 0x88B8

SESSION_FILE = "/home/student/goose-mininet/keys/secure_kem/client/active_session.json"

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def open_tap(interface_name):

    tap_fd = os.open("/dev/net/tun", os.O_RDWR)

    interface_request = struct.pack(
        "16sH",
        interface_name.encode("utf-8"),
        IFF_TAP | IFF_NO_PI
    )

    fcntl.ioctl(tap_fd, TUNSETIFF, interface_request)

    return tap_fd

with open(SESSION_FILE, "r") as session_file:
    session = json.load(session_file)

if session.get("status") != "ACTIVE":
    raise RuntimeError("No active authenticated KEM session")

aes_key = base64.b64decode(session["aes_key_b64"])

aesgcm= AESGCM(aes_key)

tap_in_fd = open_tap(TAP_IN)
tap_out_fd = open_tap(TAP_OUT)

print("encryption forwarder started")
print(f"Reading original GOOSE frames from {TAP_IN}")
print(f"Writing encrypted GOOSE frames to {TAP_OUT}")

try:
    while True:
        frame_data = os.read(tap_in_fd, 65535)
        packet = Ether(frame_data)

        if (
            packet.type == GOOSE_ETHERTYPE
            and Raw in packet
        ):
            original_payload = bytes(packet[Raw].load)

            nonce = os.urandom(12)

            encrypted_payload = aesgcm.encrypt(
                nonce,
                original_payload,
                None
            )

            new_payload = nonce + encrypted_payload

            encrypted_frame = (
                Ether(
                    src=packet.src,
                    dst=packet.dst,
                    type=GOOSE_ETHERTYPE
                )
                / Raw(load=new_payload)
            )

            os.write(tap_out_fd, bytes(encrypted_frame))

            print(
                "Encrypted and forwarded frame, "
                f"encrypted length={len(new_payload)} bytes"
            )

except KeyboardInterrupt:
    print("\nEncryption forwarder stopped")

finally:
    os.close(tap_in_fd)
    os.close(tap_out_fd)
