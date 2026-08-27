#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-44"
PROTOCOL_VERSION = 1

GROUP_ID = "GOOSE_GROUP_1"
KEY_VERSION = 2

AUTHORISED_GROUP_MEMBERS = {
    "GOOSE_GROUP_1": {
        "goose-encryption-endpoint",
    }
}

REVOKED_GROUP_MEMBERS = set()

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000
MAX_MESSAGE_SIZE = 5 * 1024 * 1024

BASE_DIRECTORY = Path("/home/student/goose-mininet/keys/secure_kem")
SERVER_DIRECTORY = BASE_DIRECTORY / "Server"

SERVER_PRIVATE_KEY_FILE = SERVER_DIRECTORY / "server_identity_private.b64"
SERVER_PUBLIC_KEY_FILE = SERVER_DIRECTORY / "server_identity_public.b64"
TRUSTED_CLIENT_PUBLIC_KEY_FILE = (
    SERVER_DIRECTORY / "trusted_client_identity_public.b64"
)
SERVER_SESSION_FILE = SERVER_DIRECTORY / "active_session.json"


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as output_file:
        output_file.write(data)

    os.chmod(path, 0o644)


def write_public_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as output_file:
        output_file.write(data)

    os.chmod(path, 0o644)


def read_base64_file(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    return decode_base64(path.read_text(encoding="ascii").strip())


def send_message(
    connection: socket.socket,
    message: dict[str, Any],
) -> None:
    encoded_message = canonical_json(message)

    if len(encoded_message) > MAX_MESSAGE_SIZE:
        raise ValueError("Outgoing message is too large")

    connection.sendall(struct.pack("!I", len(encoded_message)))
    connection.sendall(encoded_message)


def receive_exact(
    connection: socket.socket,
    required_size: int,
) -> bytes:
    received_data = bytearray()

    while len(received_data) < required_size:
        chunk = connection.recv(required_size - len(received_data))

        if not chunk:
            raise ConnectionError(
                "Connection closed before the complete message arrived"
            )

        received_data.extend(chunk)

    return bytes(received_data)


def receive_message(
    connection: socket.socket,
) -> dict[str, Any]:
    header = receive_exact(connection, 4)
    message_length = struct.unpack("!I", header)[0]

    if message_length <= 0 or message_length > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid incoming message length")

    encoded_message = receive_exact(connection, message_length)
    message = json.loads(encoded_message.decode("utf-8"))

    if not isinstance(message, dict):
        raise ValueError("Incoming message is not a JSON object")

    return message


def sign_message(
    unsigned_message: dict[str, Any],
    private_key: bytes,
    signer=None,
) -> str:
    if signer is not None:
        signature = signer.sign(canonical_json(unsigned_message))
    else:
        with oqs.Signature(
            SIGNATURE_ALGORITHM,
            private_key,
        ) as temporary_signer:
            signature = temporary_signer.sign(
                canonical_json(unsigned_message)
            )

    return encode_base64(signature)


def verify_signed_message(
    signed_message: dict[str, Any],
    trusted_public_key: bytes,
    verifier=None,
) -> dict[str, Any]:
    if "signature" not in signed_message:
        raise ValueError("Incoming message has no signature")

    unsigned_message = dict(signed_message)
    signature = decode_base64(unsigned_message.pop("signature"))

    if verifier is not None:
        valid = verifier.verify(
            canonical_json(unsigned_message),
            signature,
            trusted_public_key,
        )
    else:
        with oqs.Signature(SIGNATURE_ALGORITHM) as temporary_verifier:
            valid = temporary_verifier.verify(
                canonical_json(unsigned_message),
                signature,
                trusted_public_key,
            )

    if not valid:
        raise ValueError("Client ML-DSA signature verification failed")

    return unsigned_message


def derive_session_material(
    shared_secret: bytes,
    transcript_hash: bytes,
) -> tuple[bytes, bytes, bytes]:

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=60,
        salt=transcript_hash,
        info=b"goose-bpfabric-secure-kem-v1",
    )

    derived_material = hkdf.derive(shared_secret)

    return (
        derived_material[0:24],
        derived_material[24:56],
        derived_material[56:60],
    )


def create_confirmation(
    confirmation_key: bytes,
    label: bytes,
    transcript_hash: bytes,
) -> bytes:
    return hmac.new(
        confirmation_key,
        label + transcript_hash,
        hashlib.sha256,
    ).digest()


def initialise_identity() -> None:
    if (
        SERVER_PRIVATE_KEY_FILE.exists()
        or SERVER_PUBLIC_KEY_FILE.exists()
    ):
        raise FileExistsError(
            "Server identity already exists and has not been overwritten"
        )

    SERVER_DIRECTORY.mkdir(parents=True, exist_ok=True)

    with oqs.Signature(SIGNATURE_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    write_private_file(
        SERVER_PRIVATE_KEY_FILE,
        encode_base64(private_key).encode("ascii"),
    )

    write_public_file(
        SERVER_PUBLIC_KEY_FILE,
        encode_base64(public_key).encode("ascii"),
    )

    print("Server ML-DSA identity created")
    print(f"Private key: {SERVER_PRIVATE_KEY_FILE}")
    print(f"Public key: {SERVER_PUBLIC_KEY_FILE}")


def run_server(host: str, port: int) -> None:
    server_private_key = read_base64_file(SERVER_PRIVATE_KEY_FILE)

    trusted_client_public_key = read_base64_file(
        TRUSTED_CLIENT_PUBLIC_KEY_FILE
    )

    if SERVER_SESSION_FILE.exists():
        SERVER_SESSION_FILE.unlink()

    session_id = os.urandom(16).hex()
    server_challenge = encode_base64(os.urandom(32))

    server_signer = oqs.Signature(
        SIGNATURE_ALGORITHM,
        server_private_key,
    )

    client_verifier = oqs.Signature(
        SIGNATURE_ALGORITHM
    )

    # HKDF WARM-UP
    derive_session_material(
        os.urandom(32),
        os.urandom(32),
    )

    # TIMING: ML-KEM key generation
    keygen_start_ns = time.perf_counter_ns()

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        kem_public_key = kem.generate_keypair()

        keygen_ms = (
            time.perf_counter_ns() - keygen_start_ns
        ) / 1_000_000

        offer_core = {
            "type": "KEM_OFFER",
            "version": PROTOCOL_VERSION,
            "kem_algorithm": KEM_ALGORITHM,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "session_id": session_id,
            "group_id": GROUP_ID,
            "server_challenge": server_challenge,
            "kem_public_key": encode_base64(kem_public_key),
            "server_identity": "goose-encryption-endpoint",
        }

        sign_offer_start_ns = time.perf_counter_ns()

        signed_offer = dict(offer_core)
        signed_offer["signature"] = sign_message(
            offer_core,
            server_private_key,
            server_signer,
        )

        sign_offer_ms = (
            time.perf_counter_ns() - sign_offer_start_ns
        ) / 1_000_000

        print("Authenticated ML-KEM server starting")
        print(f"Listening on {host}:{port}")
        print(f"Session ID: {session_id}")
        print(f"GOOSE group: {GROUP_ID}")

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as listener:
            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )

            listener.bind((host, port))
            listener.listen(1)

            connection, address = listener.accept()

            handshake_start_ns = time.perf_counter_ns()

            with connection:
                connection.settimeout(30.0)

                print(
                    f"Client connected from "
                    f"{address[0]}:{address[1]}"
                )

                send_offer_start_ns = time.perf_counter_ns()
                send_message(connection, signed_offer)
                send_offer_ms = (
                    time.perf_counter_ns() - send_offer_start_ns
                ) / 1_000_000

                receive_start_ns = time.perf_counter_ns()
                signed_response = receive_message(connection)
                receive_response_ms = (
                    time.perf_counter_ns() - receive_start_ns
                ) / 1_000_000

                verify_start_ns = time.perf_counter_ns()
                response = verify_signed_message(
                    signed_response,
                    trusted_client_public_key,
                    client_verifier,
                )
                verify_client_ms = (
                    time.perf_counter_ns() - verify_start_ns
                ) / 1_000_000

                required_fields = {
                    "type",
                    "version",
                    "kem_algorithm",
                    "signature_algorithm",
                    "session_id",
                    "group_id",
                    "member_id",
                    "server_challenge",
                    "client_challenge",
                    "kem_ciphertext",
                    "client_confirmation",
                    "client_identity",
                }

                missing_fields = required_fields.difference(response)

                if missing_fields:
                    raise ValueError(
                        f"Client response missing fields: "
                        f"{sorted(missing_fields)}"
                    )

                if response["type"] != "KEM_RESPONSE":
                    raise ValueError("Unexpected client message type")

                if response["version"] != PROTOCOL_VERSION:
                    raise ValueError("Protocol version mismatch")

                if response["session_id"] != session_id:
                    raise ValueError("Session identifier mismatch")

                if response["group_id"] != GROUP_ID:
                    raise ValueError(
                        "Requested GOOSE group is not recognised"
                    )

                if response["member_id"] != response["client_identity"]:
                    raise ValueError("Member identity mismatch")

                authorised_members = AUTHORISED_GROUP_MEMBERS.get(
                    response["group_id"],
                    set(),
                )

                if response["client_identity"] in REVOKED_GROUP_MEMBERS:
                    raise ValueError(
                        f"Client {response['client_identity']} has been revoked"
                    )

                if (
                    response["client_identity"]
                    not in authorised_members
                ):
                    raise ValueError(
                        f"Client {response['client_identity']} "
                        f"is not authorised for group "
                        f"{response['group_id']}"
                    )

                print(
                    f"Client authorised for group: "
                    f"{response['group_id']}"
                )

                if response["server_challenge"] != server_challenge:
                    raise ValueError("Server challenge mismatch")

                kem_ciphertext = decode_base64(
                    response["kem_ciphertext"]
                )

                decap_start_ns = time.perf_counter_ns()
                shared_secret = kem.decap_secret(kem_ciphertext)
                decap_ms = (
                    time.perf_counter_ns() - decap_start_ns
                ) / 1_000_000

                transcript_start_ns = time.perf_counter_ns()

                response_for_transcript = {
                    key: response[key]
                    for key in (
                        "type",
                        "version",
                        "kem_algorithm",
                        "signature_algorithm",
                        "session_id",
                        "group_id",
                        "member_id",
                        "server_challenge",
                        "client_challenge",
                        "kem_ciphertext",
                        "client_identity",
                    )
                }

                transcript = {
                    "offer": offer_core,
                    "response": response_for_transcript,
                }

                transcript_hash = hashlib.sha256(
                    canonical_json(transcript)
                ).digest()

                transcript_ms = (
                    time.perf_counter_ns() - transcript_start_ns
                ) / 1_000_000

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

                confirm_start_ns = time.perf_counter_ns()

                expected_client_confirmation = create_confirmation(
                    confirmation_key,
                    b"client-confirmation",
                    transcript_hash,
                )

                received_client_confirmation = decode_base64(
                    response["client_confirmation"]
                )

                if not hmac.compare_digest(
                    expected_client_confirmation,
                    received_client_confirmation,
                ):
                    raise ValueError(
                        "Client key confirmation failed"
                    )

                confirmation_ms = (
                    time.perf_counter_ns() - confirm_start_ns
                ) / 1_000_000

                key_id = os.urandom(8).hex()

                final_core = {
                    "type": "KEM_COMPLETE",
                    "status": "ACTIVE",
                    "version": PROTOCOL_VERSION,
                    "session_id": session_id,
                    "group_id": GROUP_ID,
                    "member_id": response["member_id"],
                    "key_id": key_id,
                    "key_version": KEY_VERSION,
                    "client_challenge": response[
                        "client_challenge"
                    ],
                    "server_confirmation": encode_base64(
                        create_confirmation(
                            confirmation_key,
                            b"server-confirmation",
                            transcript_hash,
                        )
                    ),
                    "Status": "SUCCESS",
                }

                sign_final_start_ns = time.perf_counter_ns()

                signed_final = dict(final_core)
                signed_final["signature"] = sign_message(
                    final_core,
                    server_private_key,
                    server_signer,
                )

                sign_final_ms = (
                    time.perf_counter_ns() - sign_final_start_ns
                ) / 1_000_000

                send_final_start_ns = time.perf_counter_ns()
                send_message(connection, signed_final)
                send_final_ms = (
                    time.perf_counter_ns() - send_final_start_ns
                ) / 1_000_000

                handshake_ms = (
                    time.perf_counter_ns() - handshake_start_ns
                ) / 1_000_000

                session_record = {
                    "status": "ACTIVE",
                    "role": "decryption",
                    "session_id": session_id,
                    "group_id": GROUP_ID,
                    "member_id": response["member_id"],
                    "key_id": key_id,
                    "key_version": KEY_VERSION,
                    "channel_id": 1,
                    "kem_algorithm": KEM_ALGORITHM,
                    "signature_algorithm": SIGNATURE_ALGORITHM,
                    "aes_key_b64": encode_base64(aes_key),
                    "nonce_prefix_b64": encode_base64(
                        nonce_prefix
                    ),
                    "created_unix": time.time(),
                    "handshake_ms": round(handshake_ms, 3),
                }

                write_private_file(
                    SERVER_SESSION_FILE,
                    json.dumps(
                        session_record,
                        indent=4,
                        sort_keys=True,
                    ).encode("utf-8"),
                )

                print("Client identity verified")
                print("ML-KEM ciphertext decapsulated")
                print("Client key confirmation verified")
                print("Final server confirmation sent")

                print("\n--- SERVER TIMINGS ---")
                print(f"ML-KEM key generation: {keygen_ms:.3f} ms")
                print(f"ML-DSA offer signing: {sign_offer_ms:.3f} ms")
                print(f"Send offer: {send_offer_ms:.3f} ms")
                print(
                    f"Wait/receive client response: "
                    f"{receive_response_ms:.3f} ms"
                )
                print(
                    f"Verify client ML-DSA signature: "
                    f"{verify_client_ms:.3f} ms"
                )
                print(f"ML-KEM decapsulation: {decap_ms:.3f} ms")
                print(f"Transcript processing: {transcript_ms:.3f} ms")
                print(f"HKDF: {hkdf_ms:.3f} ms")
                print(
                    f"Client confirmation: "
                    f"{confirmation_ms:.3f} ms"
                )
                print(
                    f"ML-DSA final signing: "
                    f"{sign_final_ms:.3f} ms"
                )
                print(f"Send final: {send_final_ms:.3f} ms")
                print(
                    f"ONLINE HANDSHAKE TOTAL: "
                    f"{handshake_ms:.3f} ms"
                )

                print(
                    f"Session stored at: "
                    f"{SERVER_SESSION_FILE}"
                )
                print("Secure ML-KEM session established")

    server_signer.free()
    client_verifier.free()


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--init-identity",
        action="store_true",
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
    )

    arguments = parser.parse_args()

    try:
        if arguments.init_identity:
            initialise_identity()
        else:
            run_server(arguments.host, arguments.port)

        return 0

    except KeyboardInterrupt:
        print("\nServer stopped")
        return 130

    except Exception as error:
        print(
            f"Server error: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
