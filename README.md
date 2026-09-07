Quantum-Safe IEC 61850 GOOSE Protection using BPFabric
Overview
This repository contains the implementation developed for a Master’s dissertation investigating post-quantum protection of IEC 61850 GOOSE traffic in a programmable BPFabric network.
The project combines post-quantum key establishment and authentication with user-space GOOSE encryption and decryption. BPFabric and eBPF are used to redirect traffic through the cryptographic processing path.
Cryptographic Design
The implementation uses:
- ML-KEM for post-quantum shared-secret establishment.
- ML-DSA for endpoint authentication and signing KEM material.
- HKDF-SHA256 for deriving session material.
- AES-GCM for authenticated encryption of the GOOSE payload.
- A per-session nonce prefix and packet counter for unique per-packet nonces.
- Authenticated Additional Data containing the group ID, key ID and key version.
- Receiver-side counter tracking to reject replayed frames.
The KEM exchange establishes the session before normal packet transmission, so post-quantum key establishment is not performed for every GOOSE frame.
Repository Structure
bpfabric/goose_integration_topo.py
Creates the Mininet/BPFabric experimental topology, including the three switches, hosts and TAP interfaces used by the encryption and decryption paths.
bpfabric/goose_forwarder.c
Encryption-side eBPF microfunction. It identifies GOOSE traffic and redirects matching frames towards the user-space encryption process.
bpfabric/goose_decrypt_forwarder.c
Receiving-side eBPF microfunction. It redirects protected GOOSE traffic to the decryption process and returns restored traffic to the forwarding path.
scripts/kem_key_server.py
Implements the server side of the authenticated post-quantum key exchange, including ML-KEM decapsulation, ML-DSA verification, HKDF derivation and key confirmation.
scripts/kem_key_client.py
Implements the client side of the authenticated key exchange, including server verification, ML-KEM encapsulation, client authentication and session derivation.
Shared constants and helper functions are imported from kem_key_server.py for simplicity and to keep protocol handling consistent between both endpoints.
scripts/encrypt_forwarder.py
Reads GOOSE frames from the encryption TAP interface, encrypts the GOOSE payload using AES-GCM and forwards the protected frame back into BPFabric.
scripts/decrypt_forwarder.py
Receives protected frames, reconstructs the nonce, checks for replayed counters, authenticates and decrypts the payload, and restores the original GOOSE frame.
scripts/goose_sender.py
Generates controlled GOOSE test traffic containing sequence numbers and timing information for experimental evaluation.
scripts/payload_validation_receiver.py
Receives restored GOOSE frames, validates the expected payload, calculates end-to-end latency and records the experimental results.
Environment
The prototype was developed using Python 3, Mininet, BPFabric, eBPF, Linux TAP interfaces, Open Quantum Safe, Python cryptography, Scapy and Wireshark.
BPFabric is an external dependency and is not included in this repository.
Security
Private keys, active session files, derived AES keys, logs and generated experimental results are excluded from version control.
Status
The full prototype has been successfully demonstrated end-to-end, including authenticated post-quantum session establishment, GOOSE encryption, forwarding through BPFabric, decryption and successful payload validation.
This repository represents a research prototype and is not intended to be a complete production IEC 62351 or PKI implementation.
