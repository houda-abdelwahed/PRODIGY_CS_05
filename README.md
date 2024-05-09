# PRODIGY_CS_05
# Simple Packet Sniffer with Scapy

This is a simple packet sniffer script written in Python using the Scapy library. It captures network packets and displays relevant information such as source and destination IP addresses, protocols, and payload data.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)

## Usage

1. Make sure you have Python and Scapy installed on your system.

2. Run the packet sniffer script `packet_sniffer.py`.

3. The script will start capturing packets on the default network interface. You can customize the number of packets to capture by changing the `count` parameter in the `sniff` function.

## Explanation

The packet sniffer script works as follows:

- It imports necessary modules from the Scapy library to handle packet capturing and manipulation.

- It defines a packet callback function `packet_callback` that is called for each captured packet. This function checks if the packet has an IP layer (`IP`) and if so, extracts relevant information such as source and destination IP addresses, protocol, and payload data from the packet.

- It starts sniffing packets on the default network interface using the `sniff` function, specifying the packet callback function (`packet_callback`) and the number of packets to capture (`count`).

