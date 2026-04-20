#!/usr/bin/env python3
"""
Packet Collector - Captures incoming packets on victim VM and logs with system-clock timestamps.
Requires chrony (or similar) to be syncing system time against the NTP server VM.
Install: pip install scapy
Run: sudo python3 collector.py <interface> <attacker_src_ip> [output_file]
Example: sudo python3 collector.py eth0 192.168.1.10
"""

import sys, time, signal
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

class PacketCapture:
    def __init__(self, output_file="captured_packets.txt"):
        self.output_file = output_file
        self.packet_count = 0
        self.start_time = time.time()
        self.fh = open(output_file, "w", buffering=1)  # line-buffered, single open handle
        self.fh.write("capture_time,src_ip,dest_ip,protocol,src_port,dest_port,ttl,packet_size,tcp_seq,icmp_id,icmp_seq,udp_payload_id\n")

    def close(self):
        try: self.fh.close()
        except Exception: pass

    def packet_callback(self, pkt):
        if IP not in pkt: return
        capture_time = time.time()  # chrony keeps this NTP-synced; no per-packet network call
        ip_layer = pkt[IP]
        proto = ip_layer.proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        src_port = dest_port = "N/A"
        tcp_seq = icmp_id = icmp_seq = udp_payload_id = "N/A"
        if TCP in pkt:
            src_port, dest_port, tcp_seq = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq
        elif UDP in pkt:
            src_port, dest_port = pkt[UDP].sport, pkt[UDP].dport
            if Raw in pkt:
                try: udp_payload_id = pkt[Raw].load.decode("utf-8", errors="replace")
                except Exception: udp_payload_id = "N/A"
        elif ICMP in pkt:
            icmp_id, icmp_seq = pkt[ICMP].id, pkt[ICMP].seq
        self.fh.write(f"{capture_time:.6f},{ip_layer.src},{ip_layer.dst},{proto_name},{src_port},{dest_port},{ip_layer.ttl},{len(pkt)},{tcp_seq},{icmp_id},{icmp_seq},{udp_payload_id}\n")
        self.packet_count += 1
        if self.packet_count % 25 == 0:
            print(f"[+] Captured {self.packet_count} packets ({time.time() - self.start_time:.1f}s)")

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 collector.py <interface> <attacker_src_ip> [output_file]")
        print("Example: sudo python3 collector.py eth0 192.168.1.10")
        sys.exit(1)
    interface, target_src_ip = sys.argv[1], sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else "captured_packets.txt"
    print(f"[*] Interface: {interface}\n[*] Filter: src {target_src_ip}\n[*] Output: {output_file}\n[*] Press Ctrl+C to stop\n")
    capture = PacketCapture(output_file)
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    try:
        sniff(iface=interface, prn=capture.packet_callback, filter=f"src {target_src_ip}", store=False)
    except KeyboardInterrupt:
        print(f"\n[+] Stopped. {capture.packet_count} packets logged to {capture.output_file}")
    except PermissionError:
        print("[-] Must run with sudo!")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        capture.close()

if __name__ == "__main__":
    main()