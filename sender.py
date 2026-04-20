#!/usr/bin/env python3
"""
Packet Sender - Generates uniquely crafted IP packets for anomaly detection testing.
Requires: pip install scapy ntplib
Run with: sudo python3 packet_sender.py <target_ip> <num_packets>
"""

import sys
import time
import random
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw, send
from scapy.layers.inet import IP
import ntplib

def get_ntp_time():
    """Get synchronized time from NTP server."""
    try:
        client = ntplib.NTPClient()
        response = client.request('192.168.1.100', version=3, timeout=2)  # Update NTP server IP
        return response.tx_time
    except Exception as e:
        print(f"NTP sync failed: {e}. Using system time.")
        return time.time()

def generate_unique_packets(target_ip, num_packets):
    """Generate uniquely crafted packets with varying characteristics."""
    packets = []
    base_port = random.randint(10000, 50000)
    
    for i in range(num_packets):
        packet_type = i % 3  # Cycle through TCP, UDP, ICMP
        ttl = random.randint(32, 128)
        
        if packet_type == 0:  # TCP
            pkt = IP(dst=target_ip, ttl=ttl) / TCP(dport=80 + i, flags="S", seq=random.randint(0, 2**32-1))
        elif packet_type == 1:  # UDP
            pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=53 + i) / Raw(load=f"query_{i}".encode())
        else:  # ICMP
            pkt = IP(dst=target_ip, ttl=ttl) / ICMP(id=i, seq=i)
        
        packets.append((i, pkt, get_ntp_time()))
    
    return packets

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 packet_sender.py <target_ip> <num_packets>")
        print("Example: sudo python3 packet_sender.py 192.168.1.50 100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    num_packets = int(sys.argv[2])
    
    print(f"[*] Generating {num_packets} packets for {target_ip}")
    packets = generate_unique_packets(target_ip, num_packets)
    
    # Write ground truth file
    with open("attack_ground_truth.txt", "w") as f:
        f.write("packet_id,send_time,protocol,dest_port,ttl\n")
        for pkt_id, pkt, ntp_time in packets:
            proto = pkt[IP].proto
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
            dest_port = pkt[IP].payload.dport if hasattr(pkt[IP].payload, 'dport') else "N/A"
            f.write(f"{pkt_id},{ntp_time:.6f},{proto_name},{dest_port},{pkt[IP].ttl}\n")
    
    print(f"[+] Ground truth saved to attack_ground_truth.txt")
    print(f"[*] Sending packets... (NTP synchronized)")
    
    for idx, (pkt_id, pkt, ntp_time) in enumerate(packets):
        try:
            send(pkt, verbose=False)
            time.sleep(0.01)  # Small delay between packets
            if (idx + 1) % 25 == 0:
                print(f"[+] Sent {idx + 1}/{num_packets} packets")
        except Exception as e:
            print(f"[-] Error sending packet {pkt_id}: {e}")
    
    print(f"[+] All packets sent!")

if __name__ == "__main__":
    main()