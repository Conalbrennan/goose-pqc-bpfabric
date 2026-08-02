#!/usr/bin/env python3

from scapy.all import Ether, Raw, sendp
import time

INTERFACE = "h_1_1-eth0"
DEST_MAC = "01:0c:cd:01:00:00"
SRC_MAC = "00:00:00:00:00:01"
GOOSE_ETHERTYPE = 0x88B8

APP_ID = "0001"
GOCB_REF = "IED1/LLN0$GO$gcb01"
DATASET = "IED1/LLN0$Dataset01"
ST_NUM = 1
STATUS = "NORMAL"

print("Starting GOOSE sender..")

for sq_num  in range(1, 6):
    timestamp = time.time()

    payload = (
	f"app_id={APP_ID};"
	f"gocb_ref={GOCB_REF};"
	f"dataset={DATASET};"
	f"st_num={ST_NUM};"
	f"sq_num={sq_num};"
	f"timestamp={timestamp};"
	f"status={STATUS}"
    ) 

    frame = (
	Ether(
	    dst=DEST_MAC,
	    src=SRC_MAC,
   	    type=GOOSE_ETHERTYPE
	)
	/
	Raw(load=payload.encode())
    )


    print(f"Sending frame sq_num={sq_num}")


    sendp(
	frame,
	iface=INTERFACE,
	verbose=False
    )

    time.sleep(1)

print("Finished sending frames.")
