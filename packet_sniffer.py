from scapy.all import *
from scapy.layers.inet import IP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[Raw].load if packet.haslayer(Raw) else None
        
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}, Protocol: {protocol}")
        if payload:
            print("Payload:", payload)

# Start sniffing packets on the default interface
sniff(prn=packet_callback, count=10)  # Capture 10 packets
