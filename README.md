Explanation of files:

bpfabric/goose_integration_topo.py
Creates the three-switch Mininet/BPFabric topology.
It also creates the four TAP interfaces used to move packets between BPFabric and the Python encryption/decryption processes.

bpfabric/goose_forwarder.c
This runs on Switch 2.
It identifies GOOSE traffic and redirects it to the encryption TAP interface.

bpfabric/goose_decrypt_forwarder.c
Runs on Switch 3.
Redirects protected traffic to the decryption TAP interface and allows decrypted traffic back into the normal forwarding path.

scripts/kem_key_server.py
Runs the server side of the authenticated post-quantum key exchange.
It verifies the client, performs ML-KEM decapsulation, derives the AES session key and saves the server-side session file.

scripts/kem_key_client.py
Inverse of the above - runs the client side of the authenticated post-quantum key exchange.
It verifies the server, performs ML-KEM encapsulation, derives the same AES session key and saves the client-side session file.

scripts/encrypt_forwarder.py
Reads original GOOSE frames from tap_enc_in.
Encrypts them using AES-256-GCM and sends the protected frames to tap_enc_out.

scripts/decrypt_forwarder.py
Reads protected frames from tap_dec_in.
It authenticates and decrypts them, then sends the restored GOOSE frames to tap_dec_out.

scripts/goose_sender.py
This sends five test GOOSE frames from host h_1_1.
Used to start the end-to-end test.

scripts/payload_validation_receiver.py
Runs on host h_2_1.
It checks the received frames and reports validation=PASS when the payload is correct.



How to run the full test
1. Clean Mininet

Open a terminal and run:  sudo mn -c


2. Start the BPFabric controller

In the first terminal:   cd /home/student/BPFabric/controller

python3 cli.py

Leave this terminal open.


3. Start the TAP-enabled topology

Open a second terminal:   cd /home/student/BPFabric/mininet

sudo python3 goose_integration_topo.py



4. Install the eBPF functions

Return to the BPFabric controller terminal and enter:

1 add 0 learningswitch ../examples/learningswitch.o

2 add 0 goose_encrypt ../examples/goose_forwarder.o

3 add 0 goose_decrypt ../examples/goose_decrypt_forwarder.o


5. Start the authenticated KEM server

Open a third terminal:   cd /home/student/goose-pqc-bpfabric/scripts

python3 kem_key_server.py --port 9100



6. Run the authenticated KEM client

Open a fourth terminal:   cd /home/student/goose-pqc-bpfabric/scripts

python3 kem_key_client.py --server-port 9100

If successful, handshake should end with "Secure ML-KEM session established"


7. Start the encryption forwarder

Open a fifth terminal: cd /home/student/goose-pqc-bpfabric/scripts

python3 encrypt_forwarder.py



8. Start the decryption forwarder

Open a sixth terminal:  cd /home/student/goose-pqc-bpfabric/scripts

python3 decrypt_forwarder.py



9. Open the sender and receiver hosts

At the Mininet prompt, run:

xterm h_1_1 h_2_1

This opens one terminal for the sender and one for the receiver.


10. Start the receiver

In the h_2_1 terminal:   cd /home/student/goose-pqc-bpfabric/scripts

python3 payload_validation_receiver.py



11. Send the test frames

In the h_1_1 terminal:  cd /home/student/goose-pqc-bpfabric/scripts

python3 goose_sender.py


Expected result

5 GOOSE frames sent

5 frames encrypted

5 frames decrypted

5 validation=PASS results
