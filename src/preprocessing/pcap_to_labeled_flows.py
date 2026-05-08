#!/usr/bin/env python3
"""
pcap_to_labeled_flows.py (Updated)
========================
Converts .pcap files (or whole directories) into a single labeled flows CSV.
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import glob

import numpy as np
import pandas as pd

# Label mapping: ground truth attack_type -> CIC-IDS2017 model label
LABEL_MAP = {
    "benign":           "BENIGN",
    "port_scan":        "PortScan",
    "portscan":         "PortScan",
    "port_scan_udp":    "PortScan",
    "ddos_syn":         "DDoS",
    "ddos_icmp":        "DDoS",
    "ddos_udp":         "DDoS",
    "ddos":             "DDoS",
    "tcp_syn_flood":    "DDoS",
    "dos_slowloris":    "DoS slowloris",
    "slowloris":        "DoS slowloris",
    "slow_lorris":      "DoS slowloris",
    "dos_slowhttptest": "DoS Slowhttptest",
    "slowhttptest":     "DoS Slowhttptest",
    "dos_goldeneye":    "DoS GoldenEye",
    "goldeneye":        "DoS GoldenEye",
    "dos_hulk":         "DoS Hulk",
    "hulk":             "DoS Hulk",
    "ssh_brute":        "SSH-Patator",
    "ssh_patator":      "SSH-Patator",
    "ftp_brute":        "FTP-Patator",
    "ftp_patator":      "FTP-Patator",
    "botnet_beacon":    "Bot",
    "botnet":           "Bot",
    "bot":              "Bot",
    "web_xss":          "Web Attack XSS",
    "web_sqli":         "Web Attack Sql Injection",
    "web_brute":        "Web Attack Brute Force",
}

def run_cicflowmeter(pcap_path: str, out_csv: str) -> None:
    candidates = [
        ["uv", "tool", "run", "cicflowmeter", "-f", pcap_path, "-c", out_csv],
        ["cicflowmeter",                       "-f", pcap_path, "-c", out_csv],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 or (
                os.path.isfile(out_csv) and os.path.getsize(out_csv) > 0
            ):
                return
        except FileNotFoundError:
            continue
    sys.exit("[-] CICFlowMeter not found. Install: uv tool install git+https://github.com/hieulw/cicflowmeter")

def load_ground_truth(gt_path: str) -> pd.DataFrame:
    gt = pd.read_csv(gt_path)
    gt.columns = gt.columns.str.strip()
    for col in ("attack_type", "start_time", "end_time"):
        if col not in gt.columns:
            sys.exit(f"[-] Ground truth missing required column: '{col}'")

    gt["label"] = gt["attack_type"].str.strip().str.lower().map(LABEL_MAP)
    unmapped = gt[gt["label"].isna()]["attack_type"].unique()
    if len(unmapped):
        print(f"[!] Unmapped attack_type(s) — used as-is: {list(unmapped)}")
        gt["label"] = gt["label"].fillna(gt["attack_type"])

    gt["start_time"] = pd.to_numeric(gt["start_time"])
    gt["end_time"]   = pd.to_numeric(gt["end_time"])
    return gt

def assign_labels(df: pd.DataFrame, gt: pd.DataFrame) -> pd.DataFrame:
    ts_col = next((c for c in df.columns if c.lower() in ("timestamp", "ts", "flow_start_time")), None)
    if ts_col is None:
        df["Label"] = "BENIGN"
        return df

    ts = pd.to_numeric(df[ts_col], errors="coerce")
    if ts.median() > 2e12: ts = ts / 1e6 # Handle microsecond timestamps

    labels = pd.Series(["BENIGN"] * len(df), index=df.index, dtype=str)
    for _, row in gt.iterrows():
        mask = (ts >= row["start_time"]) & (ts <= row["end_time"])
        labels[mask] = row["label"]

    df["Label"] = labels
    return df

def apply_rename(df: pd.DataFrame, rename_pkl: str) -> pd.DataFrame:
    with open(rename_pkl, "rb") as fh:
        rename_map = pickle.load(fh)
    df.rename(columns=rename_map, inplace=True)
    if "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    return df

def process_pcap(pcap_path: str, gt: pd.DataFrame | None, forced_label: str | None, tmp_dir: str) -> pd.DataFrame | None:
    name = os.path.basename(pcap_path)
    print(f"[*] Processing: {name}")
    raw_csv = os.path.join(tmp_dir, f"{os.path.splitext(name)[0]}_raw.csv")
    run_cicflowmeter(pcap_path, raw_csv)

    if not os.path.isfile(raw_csv) or os.path.getsize(raw_csv) == 0:
        return None

    df = pd.read_csv(raw_csv, low_memory=False)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    if forced_label:
        df["Label"] = forced_label
    elif gt is not None:
        df = assign_labels(df, gt)
    else:
        df["Label"] = "BENIGN"
    
    return df

def main() -> None:
    parser = argparse.ArgumentParser(description="PCAPs/Dirs -> labeled flows CSV")
    parser.add_argument("--pcap", required=True, nargs="+", help="PCAP files or directories")
    parser.add_argument("--gt", help="Ground truth CSV")
    parser.add_argument("--label", help="Force label for all flows")
    parser.add_argument("--rename", required=True, help="rename_map.pkl")
    parser.add_argument("--out", default="labeled_flows.csv", help="Output CSV")
    args = parser.parse_args()

    # 1. Resolve all PCAP files (handle directories)
    pcap_files = []
    for path in args.pcap:
        if os.path.isdir(path):
            found = glob.glob(os.path.join(path, "*.pcap")) + glob.glob(os.path.join(path, "*.pcapng"))
            pcap_files.extend(found)
        elif os.path.isfile(path):
            pcap_files.append(path)
    
    if not pcap_files:
        sys.exit("[-] No PCAP files found.")

    print(f"[*] Found {len(pcap_files)} PCAP file(s).")
    gt = load_ground_truth(args.gt) if args.gt else None

    # 2. Process everything
    frames = []
    with tempfile.TemporaryDirectory() as tmp:
        for pcap in pcap_files:
            df = process_pcap(pcap, gt, args.label, tmp)
            if df is not None:
                frames.append(df)

    if not frames:
        sys.exit("[-] No flows extracted.")

    # 3. Merge and Rename
    merged = pd.concat(frames, ignore_index=True)
    merged = apply_rename(merged, args.rename)

    print(f"\n[+] Final distribution:")
    print(merged["Label"].value_counts())
    merged.to_csv(args.out, index=False)
    print(f"\n[+] Saved to {args.out}")

if __name__ == "__main__":
    main()