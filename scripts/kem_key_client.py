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

    print("Authenticated ML-KEM client starting")
    print(f"Connecting to {server_host}:{server_port}")
    print(f"Requesting GOOSE group: {GROUP_ID}")
    print(f"Member identity: {MEMBER_ID}")

    # OPTIMISATION:
    # Create reusable cryptographic contexts before
    # the timed handshake begins.
    client_signer = oqs.Signature(
        SIGNATURE_ALGORITHM,
        client_private_key,
    )

    server_verifier = oqs.Signature(
        SIGNATURE_ALGORITHM
    )

    kem = oqs.KeyEncapsulation(
        KEM_ALGORITHM
    )

    # TIMING: overall handshake begins immediately
    # before attempting the TCP connection.
    handshake_start_ns = time.perf_counter_ns()

    connect_start_ns = time.perf_counter_ns()

    with socket.create_connection(
        (server_host, server_port),
        timeout=30.0
    ) as connection:

        connect_ms = (
            time.perf_counter_ns() - connect_start_ns
        ) / 1_000_000

        connection.settimeout(30.0)

        receive_offer_start_ns = time.perf_counter_ns()
        signed_offer = receive_message(connection)
        receive_offer_ms = (
            time.perf_counter_ns() - receive_offer_start_ns
        ) / 1_000_000

        verify_offer_start_ns = time.perf_counter_ns()

        offer = verify_signed_message(
            signed_offer,
            trusted_server_public_key,
            server_verifier,
        )

        verify_offer_ms = (
            time.perf_counter_ns() - verify_offer_start_ns
        ) / 1_000_000

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

        # TIMING: ML-KEM encapsulation.
        # The KEM object already exists.
        encap_start_ns = time.perf_counter_ns()

        kem_ciphertext, shared_secret = kem.encap_secret(
            kem_public_key
        )

        encap_ms = (
            time.perf_counter_ns() - encap_start_ns
        ) / 1_000_000

        transcript_start_ns = time.perf_counter_ns()

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

        transcript_ms = (
            time.perf_counter_ns() - transcript_start_ns
        ) / 1_000_000

        # TIMING: HKDF
        hkdf_start_ns = time.perf_counter_ns()

        (
            aes_key,
            confirmation_key,
            nonce_prefix,
        ) = derive_session_material(
            shared_secret,
            transcript_hash,
        )

        hkdf_ms = (
            time.perf_counter_ns() - hkdf_start_ns
        ) / 1_000_000

        confirmation_start_ns = time.perf_counter_ns()

        response = dict(response_for_transcript)

        response["client_confirmation"] = encode_base64(
            create_confirmation(
                confirmation_key,
                b"client-confirmation",
                transcript_hash,
            )
        )

        client_confirmation_ms = (
            time.perf_counter_ns() - confirmation_start_ns
        ) / 1_000_000

        # TIMING: ML-DSA client response signing.
        # The signer object already exists.
        sign_start_ns = time.perf_counter_ns()

        signed_response = dict(response)

        signed_response["signature"] = sign_message(
            response,
            client_private_key,
            client_signer,
        )

        sign_response_ms = (
            time.perf_counter_ns() - sign_start_ns
        ) / 1_000_000

        send_response_start_ns = time.perf_counter_ns()
        send_message(connection, signed_response)
        send_response_ms = (
            time.perf_counter_ns() - send_response_start_ns
        ) / 1_000_000

        print("ML-KEM encapsulation completed")
        print("Signed KEM ciphertext sent")

        receive_final_start_ns = time.perf_counter_ns()
        signed_final = receive_message(connection)
        receive_final_ms = (
            time.perf_counter_ns() - receive_final_start_ns
        ) / 1_000_000

        verify_final_start_ns = time.perf_counter_ns()

        final_message = verify_signed_message(
            signed_final,
            trusted_server_public_key,
            server_verifier,
        )

        verify_final_ms = (
            time.perf_counter_ns() - verify_final_start_ns
        ) / 1_000_000

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

        server_confirmation_start_ns = time.perf_counter_ns()

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

        server_confirmation_ms = (
            time.perf_counter_ns() - server_confirmation_start_ns
        ) / 1_000_000

        handshake_ms = (
            time.perf_counter_ns() - handshake_start_ns
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
            "handshake_ms": round(handshake_ms, 3),
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

        print("\n--- CLIENT TIMINGS ---")
        print(f"TCP connection: {connect_ms:.3f} ms")
        print(f"Receive server offer: {receive_offer_ms:.3f} ms")
        print(
            f"Verify server ML-DSA signature: "
            f"{verify_offer_ms:.3f} ms"
        )
        print(f"ML-KEM encapsulation: {encap_ms:.3f} ms")
        print(f"Transcript processing: {transcript_ms:.3f} ms")
        print(f"HKDF: {hkdf_ms:.3f} ms")
        print(
            f"Client confirmation: "
            f"{client_confirmation_ms:.3f} ms"
        )
        print(
            f"ML-DSA client response signing: "
            f"{sign_response_ms:.3f} ms"
        )
        print(
            f"Send client response: "
            f"{send_response_ms:.3f} ms"
        )
        print(
            f"Wait/receive final message: "
            f"{receive_final_ms:.3f} ms"
        )
        print(
            f"Verify final ML-DSA signature: "
            f"{verify_final_ms:.3f} ms"
        )
        print(
            f"Server confirmation: "
            f"{server_confirmation_ms:.3f} ms"
        )
        print(
            f"CLIENT HANDSHAKE TOTAL: "
            f"{handshake_ms:.3f} ms"
        )

        print(f"Session stored at: {CLIENT_SESSION_FILE}")
        print("Secure ML-KEM group session established")

    # Explicitly release pre-created contexts.
    client_signer.free()
    server_verifier.free()
    kem.free()


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
