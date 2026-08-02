#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.link import Intf

from eBPFSwitch import eBPFSwitch, eBPFHost

import subprocess

#Map each TAP interface to the BPFabric edge switch, the encryption pair is attached to 23 and decryption pair to s3
TAP_INTERFACES = [
    ("tap_enc_in", "s2"),
    ("tap_enc_out", "s2"),
    ("tap_dec_in", "s3"),
    ("tap_dec_out", "s3"),
]

#Define the three switch  topology
class ThreeSwitchTopo(Topo):

    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Core forwarding switch
        coreSwitch = self.addSwitch(
            "s1",
            switch_path="../softswitch/softswitch"
        )

        # Encryption side edge switch
        aggSwitch1 = self.addSwitch(
            "s2",
            switch_path="../softswitch/softswitch"
        )

	# Decryption side edge switch
        aggSwitch2 = self.addSwitch(
            "s3",
            switch_path="../softswitch/softswitch"
        )

        # Sender side hosts connected to the encryption edge switch
        h_1_1 = self.addHost(
            "h_1_1",
            ip="10.0.1.1/8",
            mac="00:04:00:00:01:01"
        )
        self.addLink(h_1_1, aggSwitch1)

	# Connect the encryption edge switch to the core switch
        self.addLink(aggSwitch1, coreSwitch)

        h_1_2 = self.addHost(
            "h_1_2",
            ip="10.0.1.2/8",
            mac="00:04:00:00:01:02"
        )
        self.addLink(h_1_2, aggSwitch1)

        # Connect the decryption edge switch to the core switch

        self.addLink(aggSwitch2, coreSwitch)

	# Receiver side hosts connected to the decryption edge switch
        h_2_1 = self.addHost(
            "h_2_1",
            ip="10.0.2.1/8",
            mac="00:04:00:00:02:01"
        )
        self.addLink(h_2_1, aggSwitch2)

        h_2_2 = self.addHost(
            "h_2_2",
            ip="10.0.2.2/8",
            mac="00:04:00:00:02:02"
        )
        self.addLink(h_2_2, aggSwitch2)

def create_tap(name, switch):
    # Remove a stale interface Left by an earlier run
    subprocess.run(
        ["ip", "tuntap", "del", "dev", name, "mode", "tap"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    subprocess.check_call(
        [
            "ip", "tuntap", "add",
            "dev", name,
            "mode", "tap",
            "user", "student"
        ]
    )

    subprocess.check_call(
        ["ip", "link", "set", "dev", name, "up"]
    )
    # Register the TAP device as a mininet interface on the selected switch
    Intf(name, node=switch)

    print("Created {} and attached it to {}".format(name, switch.name))

def delete_tap(name):
    """
    Remove a TAP interface when Mininet stops
    """

    subprocess.run(
        ["ip", "tuntap", "del", "dev", name, "mode", "tap"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def main():
    topo = ThreeSwitchTopo()

    # Create the mininet network using the BPFabric host and switch classes
    net = Mininet(
        topo=topo,
        host=eBPFHost,
        switch=eBPFSwitch,
        controller=None
    )

    # Create and attach the enryption side and decryption side TAP interfaces
    try:
        for tap_name, switch_name in TAP_INTERFACES:
            create_tap(tap_name, net.get(switch_name))

        net.start()
        CLI(net)

    finally:
        net.stop()

        for tap_name, switch_name in TAP_INTERFACES:
            delete_tap(tap_name)

if __name__ == "__main__":
    main()
