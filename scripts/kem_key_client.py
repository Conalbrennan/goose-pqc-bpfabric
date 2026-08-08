#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import socket
import sys
import time
from pathlib import Path

import oqs

from kem_key_server import (
    KEM_ALGORITHM,
    SIGNATURE_ALGORITHM,
    PROTOCOL_VERSION,
    GROUP_ID,
    encode_base64,
    decode_base64,
    canonical_json,
    write_private_file,
    write_public_file,
    read_base64_file,
    send_message,
    receive_message,
    sign_message,
    verify_signed_message,
    derive_session_material,
    create_confirmation,
)

DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 9000

MEMBER_ID = "goose-encryption-endpoint"

BASE_DIRECTORY = Path("/home/student/goose-mininet/keys/secure_kem")
CLIENT_DIRECTORY = BASE_DIRECTORY / "client"

CLIENT_PRIVATE_KEY_FILE = CLIENT_DIRECTORY / "client_identity_private.b64"
CLIENT_PUBLIC_KEY_FILE = CLIENT_DIRECTORY / "client_identity_public.b64"

TRUSTED_SERVER_PUBLIC_KEY_FILE = (
    CLIENT_DIRECTORY / "trusted_server_identity_public.b64"
)

CLIENT_SESSION_FILE = CLIENT_DIRECTORY / "active_session.json"


def initialise_identity() -> None:
    if CLIENT_PRIVATE_KEY_FILE.exists() or CLIENT_PUBLIC_KEY_FILE.exists():
        raise FileExistsError(
            "Client identity already exists and has not been overwritten"
        )

    CLIENT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    with oqs.Signature(SIGNATURE_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    write_private_file(
        CLIENT_PRIVATE_KEY_FILE,
        encode_base64(private_key).encode("ascii")
    )

    write_public_file(
        CLIENT_PUBLIC_KEY_FILE,
        encode_base64(public_key).encode("ascii")
    )

    print("Client ML-DSA identity created")
    print(f"Private key: {CLIENT_PRIVATE_KEY_FILE}")
    print(f"Public key: {CLIENT_PUBLIC_KEY_FILE}")


def run_client(server_host: str, server_port: int) -> None:
    client_private_key = read_base64_file(CLIENT_PRIVATE_KEY_FILE)

    trusted_server_public_key = read_base64_file(
        TRUSTED_SERVER_PUBLIC_KEY_FILE
    )

    if CLIENT_SESSION_FILE.exists():
        CLIENT_SESSION_FILE.unlink()

    start_time_ns = time.perf_counter_ns()

    print("Authenticated ML-KEM client starting")
    print(f"Connecting to {server_host}:{server_port}")
    print(f"Requesting GOOSE group: {GROUP_ID}")
    print(f"Member identity: {MEMBER_ID}")

    with socket.create_connection(
        (server_host, server_port),
        timeout=30.0
    ) as connection:
        connection.settimeout(30.0)

        signed_offer = receive_message(connection)

        offer = verify_signed_message(
            signed_offer,
            trusted_server_public_key,
        )

        if offer["type"] != "KEM_OFFER":
            raise ValueError("Unexpected server message type")

        if offer["version"] != PROTOCOL_VERSION:
            raise ValueError("Version mismatch")

        if offer["kem_algorithm"] != KEM_ALGORITHM:
            raise ValueError("KEM algorithm mismatch")

        if offer["signature_algorithm"] != SIGNATURE_ALGORITHM:
            raise ValueError("Signature algorithm mismatch")

        if offer.get("group_id") != GROUP_ID:
            raise ValueError(
                "Server offered an unexpected GOOSE group"
            )

        print("Server identity verified")
        print("Signed ML-KEM public key accepted")
        print(f"GOOSE group verified: {GROUP_ID}")

        kem_public_key = decode_base64(offer["kem_public_key"])
        client_challenge = encode_base64(os.urandom(32))

        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(
                kem_public_key
            )

        response_for_transcript = {
            "type": "KEM_RESPONSE",
            "version": PROTOCOL_VERSION,
            "kem_algorithm": KEM_ALGORITHM,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "session_id": offer["session_id"],
            "group_id": GROUP_ID,
            "member_id": MEMBER_ID,
            "server_challenge": offer["server_challenge"],
            "client_challenge": client_challenge,
            "kem_ciphertext": encode_base64(kem_ciphertext),
            "client_identity": MEMBER_ID,
        }

        transcript = {
            "offer": offer,
            "response": response_for_transcript,
        }

        transcript_hash = hashlib.sha256(
            canonical_json(transcript)
        ).digest()

        (
            aes_key,
            confirmation_key,
            nonce_prefix,
        ) = derive_session_material(
            shared_secret,
            transcript_hash,
        )

        response = dict(response_for_transcript)

        response["client_confirmation"] = encode_base64(
            create_confirmation(
                confirmation_key,
                b"client-confirmation",
                transcript_hash,
            )
        )

        signed_response = dict(response)

        signed_response["signature"] = sign_message(
            response,
            client_private_key,
        )

        send_message(connection, signed_response)

        print("ML-KEM encapsulation completed")
        print("Signed KEM ciphertext sent")

        signed_final = receive_message(connection)

        final_message = verify_signed_message(
            signed_final,
            trusted_server_public_key,
        )

        if final_message["type"] != "KEM_COMPLETE":
            raise ValueError("Unexpected final message type")

        if final_message["session_id"] != offer["session_id"]:
            raise ValueError("Final session identifier mismatch")

        if final_message.get("group_id") != GROUP_ID:
            raise ValueError(
                "Final GOOSE group identifier mismatch"
            )

        if final_message.get("member_id") != MEMBER_ID:
            raise ValueError(
                "Final member identifier mismatch"
            )

        if "key_id" not in final_message:
            raise ValueError(
                "Final message has no key identifier"
            )

        if "key_version" not in final_message:
            raise ValueError(
                "Final message has no key version"
            )

        if final_message["client_challenge"] != client_challenge:
            raise ValueError("Client challenge mismatch")

        if final_message["status"] != "ACTIVE":
            raise ValueError("Server did not activate the session")

        expected_server_confirmation = create_confirmation(
            confirmation_key,
            b"server-confirmation",
            transcript_hash,
        )

        received_server_confirmation = decode_base64(
            final_message["server_confirmation"]
        )

        if not hmac.compare_digest(
            expected_server_confirmation,
            received_server_confirmation,
        ):
            raise ValueError("Server key confirmation failed")

        elapsed_ms = (
            time.perf_counter_ns() - start_time_ns
        ) / 1_000_000

        session_record = {
            "status": "ACTIVE",
            "role": "encryption",
            "session_id": offer["session_id"],
            "group_id": GROUP_ID,
            "member_id": MEMBER_ID,
            "key_id": final_message["key_id"],
            "key_version": final_message["key_version"],
            "channel_id": 1,
            "kem_algorithm": KEM_ALGORITHM,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "aes_key_b64": encode_base64(aes_key),
            "nonce_prefix_b64": encode_base64(nonce_prefix),
            "transcript_hash_b64": encode_base64(
                transcript_hash
            ),
            "created_unix": time.time(),
            "handshake_ms": round(elapsed_ms, 3),
        }

        write_private_file(
            CLIENT_SESSION_FILE,
            json.dumps(
                session_record,
                indent=4,
                sort_keys=True,
            ).encode("utf-8"),
        )

        print("Server key confirmation verified")
        print(f"GOOSE group authorised: {GROUP_ID}")
        print(f"Key ID: {final_message['key_id']}")
        print(
            f"Key version: "
            f"{final_message['key_version']}"
        )
        print(f"Handshake time: {elapsed_ms:.3f} ms")
        print(f"Session stored at: {CLIENT_SESSION_FILE}")
        print("Secure ML-KEM group session established")


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--init-identity",
        action="store_true",
    )

    parser.add_argument(
        "--server-host",
        default=DEFAULT_SERVER_HOST,
    )

    parser.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_SERVER_PORT,
    )

    arguments = parser.parse_args()

    try:
        if arguments.init_identity:
            initialise_identity()
        else:
            run_client(
                arguments.server_host,
                arguments.server_port,
            )

        return 0

    except KeyboardInterrupt:
        print("\nClient stopped")
        return 130

    except Exception as error:
        print(
            f"Client error: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
