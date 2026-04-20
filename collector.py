#!/usr/bin/env python3
"""
Packet Receiver - Captures incoming packets and logs with NTP-synchronized timestamps.
Requires: pip install scapy ntplib
Run with: sudo python3 packet_receiver.py <interface> <target_src_ip>
Example: sudo python3 packet_receiver.py eth0 192.168.1.10
"""

import sys
import time
import ntplib
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

class PacketCapture:
    def __init__(self, output_file="captured_packets.txt"):
        self.output_file = output_file
        self.packet_count = 0
        self.start_time = time.time()
        
        # Write header
        with open(output_file, "w") as f:
            f.write("capture_time,src_ip,dest_ip,protocol,src_port,dest_port,ttl,packet_size\n")
    
    def get_ntp_time(self):
        """Get synchronized time from NTP server."""
        try:
            client = ntplib.NTPClient()
            response = client.request('192.168.1.100', version=3, timeout=2)  # Update NTP server IP
            return response.tx_time
        except Exception as e:
            return time.time()
    
    def packet_callback(self, pkt):
        """Callback for each captured packet."""
        if IP not in pkt:
            return
        
        ip_layer = pkt[IP]
        proto = ip_layer.proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        
        src_port = dest_port = "N/A"
        if TCP in pkt or UDP in pkt:
            payload = pkt[TCP] if TCP in pkt else pkt[UDP]
            src_port = payload.sport
            dest_port = payload.dport
        
        capture_time = self.get_ntp_time()
        packet_size = len(pkt)
        
        # Log to file
        with open(self.output_file, "a") as f:
            f.write(f"{capture_time:.6f},{ip_layer.src},{ip_layer.dst},{proto_name},{src_port},{dest_port},{ip_layer.ttl},{packet_size}\n")
        
        self.packet_count += 1
        if self.packet_count % 25 == 0:
            elapsed = time.time() - self.start_time
            print(f"[+] Captured {self.packet_count} packets ({elapsed:.1f}s)")

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 packet_receiver.py <interface> <target_src_ip>")
        print("Example: sudo python3 packet_receiver.py eth0 192.168.1.10")
        sys.exit(1)
    
    interface = sys.argv[1]
    target_src_ip = sys.argv[2]
    
    print(f"[*] Starting packet capture on {interface}")
    print(f"[*] Filtering for packets from {target_src_ip}")
    print(f"[*] Output: captured_packets.txt")
    print(f"[*] Press Ctrl+C to stop\n")
    
    capture = PacketCapture()
    
    # BPF filter: capture only from target source IP
    bpf_filter = f"src {target_src_ip}"
    
    try:
        sniff(iface=interface, prn=capture.packet_callback, filter=bpf_filter, store=False)
    except KeyboardInterrupt:
        print(f"\n[+] Capture stopped. {capture.packet_count} packets logged to {capture.output_file}")
    except PermissionError:
        print("[-] Must run with sudo!")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
