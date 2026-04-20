#!/usr/bin/env python3
"""
Packet Sender - Generates uniquely crafted IP packets for anomaly detection testing.
Timestamps are captured AFTER send() so ground truth reflects actual wire time.
Requires chrony (or similar) syncing system time against the NTP server VM.
Install: pip install scapy
Run: sudo python3 sender.py <target_ip> <num_packets> [inter_packet_delay_s]
Example: sudo python3 sender.py 192.168.1.50 100 0.01
"""

import sys, time, random
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

def build_packet(i, target_ip):
    """Build one packet; return (pkt, proto_name, dest_port, ttl, unique_id_fields_dict)."""
    ttl = random.randint(32, 128)
    ptype = i % 3
    if ptype == 0:  # TCP SYN
        dport = 1024 + ((80 + i) % (65535 - 1024))  # keep in valid range, avoid low privileged ports
        seq = random.randint(0, 2**32 - 1)
        pkt = IP(dst=target_ip, ttl=ttl) / TCP(dport=dport, flags="S", seq=seq)
        return pkt, "TCP", dport, ttl, {"tcp_seq": seq, "icmp_id": "N/A", "icmp_seq": "N/A", "udp_payload_id": "N/A"}
    elif ptype == 1:  # UDP with identifiable payload
        dport = 1024 + ((53 + i) % (65535 - 1024))
        payload = f"query_{i}"
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=dport) / Raw(load=payload.encode())
        return pkt, "UDP", dport, ttl, {"tcp_seq": "N/A", "icmp_id": "N/A", "icmp_seq": "N/A", "udp_payload_id": payload}
    else:  # ICMP echo with id/seq set to i
        icmp_id = i % 65536
        icmp_seq = i % 65536
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP(id=icmp_id, seq=icmp_seq)
        return pkt, "ICMP", "N/A", ttl, {"tcp_seq": "N/A", "icmp_id": icmp_id, "icmp_seq": icmp_seq, "udp_payload_id": "N/A"}

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 sender.py <target_ip> <num_packets> [inter_packet_delay_s]")
        print("Example: sudo python3 sender.py 192.168.1.50 100 0.01")
        sys.exit(1)
    target_ip = sys.argv[1]
    num_packets = int(sys.argv[2])
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.01
    print(f"[*] Target: {target_ip}\n[*] Count: {num_packets}\n[*] Inter-packet delay: {delay}s\n[*] Output: attack_ground_truth.txt\n")
    with open("attack_ground_truth.txt", "w", buffering=1) as f:
        f.write("packet_id,send_time,protocol,dest_port,ttl,tcp_seq,icmp_id,icmp_seq,udp_payload_id\n")
        for i in range(num_packets):
            pkt, proto_name, dport, ttl, ids = build_packet(i, target_ip)
            try:
                send(pkt, verbose=False)
                send_time = time.time()  # captured AFTER send() returns -> matches wire time closely
            except Exception as e:
                print(f"[-] Error sending packet {i}: {e}")
                continue
            f.write(f"{i},{send_time:.6f},{proto_name},{dport},{ttl},{ids['tcp_seq']},{ids['icmp_id']},{ids['icmp_seq']},{ids['udp_payload_id']}\n")
            if (i + 1) % 25 == 0:
                print(f"[+] Sent {i + 1}/{num_packets}")
            if delay > 0: time.sleep(delay)
    print(f"[+] Done. Ground truth written to attack_ground_truth.txt")

if __name__ == "__main__":
    main()