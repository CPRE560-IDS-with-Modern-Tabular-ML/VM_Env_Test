#!/usr/bin/env python3
"""
pcap_to_labeled_flows.py
========================
Converts .pcap files or directories into a single labeled flows CSV.
Optimized for the IDS-ML repository structure.

Run from project root:
  python3 src/preprocessing/pcap_to_labeled_flows.py \
      --pcap data/raw_pcaps/ \
      --gt data/attack_ground_truth.csv \
      --rename src/preprocessing/rename_map.pkl \
      --out data/flows.csv
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

# Updated to match attack.py types exactly
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
    "web_brute":        "Web Attack Brute Force",
    "web_xss":          "Web Attack XSS",
    "web_sqli":         "Web Attack Sql Injection",
}

def run_cicflowmeter(pcap_path: str, out_csv: str) -> None:
    """Invokes cicflowmeter tool via uv or shell."""
    cmds = [
        ["uv", "tool", "run", "cicflowmeter", "-f", pcap_path, "-c", out_csv],
        ["cicflowmeter", "-f", pcap_path, "-c", out_csv]
    ]
    for cmd in cmds:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0 or (os.path.isfile(out_csv) and os.path.getsize(out_csv) > 0):
                return
        except FileNotFoundError:
            continue
    sys.exit("[-] CICFlowMeter not found. Is it installed?")

def load_ground_truth(gt_path: str) -> pd.DataFrame:
    """Loads and cleans the attack_ground_truth.csv from attack.py."""
    gt = pd.read_csv(gt_path)
    gt.columns = gt.columns.str.strip()
    
    # Map the attack_type to CIC-IDS labels
    gt["label"] = gt["attack_type"].str.strip().str.lower().map(LABEL_MAP)
    
    # If we didn't find a mapping, keep the original name but warn
    unmapped = gt[gt["label"].isna()]["attack_type"].unique()
    if len(unmapped):
        print(f"[!] Warning: No mapping for {list(unmapped)}. Using raw name.")
        gt["label"] = gt["label"].fillna(gt["attack_type"])
        
    gt["start_time"] = pd.to_numeric(gt["start_time"])
    gt["end_time"] = pd.to_numeric(gt["end_time"])
    return gt

def assign_labels(df: pd.DataFrame, gt: pd.DataFrame) -> pd.DataFrame:
    """Matches flow timestamps against attack ground truth windows."""
    ts_col = next((c for c in df.columns if c.lower() in ("timestamp", "ts", "flow_start_time")), None)
    if ts_col is None:
        df["Label"] = "BENIGN"
        return df

    ts = pd.to_numeric(df[ts_col], errors="coerce")
    if ts.median() > 2e12: ts = ts / 1e6  # Convert microseconds to seconds if needed

    # Default to BENIGN
    labels = pd.Series(["BENIGN"] * len(df), index=df.index, dtype=str)
    
    # Overwrite with attack labels based on time fences
    for _, row in gt.iterrows():
        mask = (ts >= row["start_time"]) & (ts <= row["end_time"])
        labels[mask] = row["label"]

    df["Label"] = labels
    return df

def apply_rename(df: pd.DataFrame, rename_pkl: str) -> pd.DataFrame:
    """Renames CICFlowMeter columns to match the ML model expectations."""
    with open(rename_pkl, "rb") as fh:
        rename_map = pickle.load(fh)
    df.rename(columns=rename_map, inplace=True)
    # Common fix for duplicated header length column in some CIC versions
    if "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    return df

def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP Directory to Labeled CSV")
    parser.add_argument("--pcap", required=True, nargs="+", help="Files or directories of PCAPs")
    parser.add_argument("--gt", help="Path to attack_ground_truth.csv")
    parser.add_argument("--label", help="Force a specific label (overrides GT)")
    parser.add_argument("--rename", required=True, help="Path to rename_map.pkl")
    parser.add_argument("--out", default="labeled_flows.csv", help="Output filename")
    args = parser.parse_args()

    # Expand directories into a list of .pcap files
    all_pcaps = []
    for p in args.pcap:
        if os.path.isdir(p):
            all_pcaps.extend(glob.glob(os.path.join(p, "*.pcap*")))
        else:
            all_pcaps.append(p)
    
    if not all_pcaps:
        sys.exit("[-] No PCAP files found in provided paths.")

    print(f"[*] Found {len(all_pcaps)} PCAPs. Processing...")
    gt = load_ground_truth(args.gt) if args.gt else None
    
    all_frames = []
    with tempfile.TemporaryDirectory() as tmp:
        for pcap in all_pcaps:
            raw_csv = os.path.join(tmp, f"{os.path.basename(pcap)}.csv")
            run_cicflowmeter(pcap, raw_csv)
            
            if os.path.exists(raw_csv):
                df = pd.read_csv(raw_csv)
                df.columns = df.columns.str.strip()
                df.replace([np.inf, -np.inf], np.nan, inplace=True)
                
                # Labeling logic
                if args.label:
                    df["Label"] = args.label
                elif gt is not None:
                    df = assign_labels(df, gt)
                else:
                    df["Label"] = "BENIGN"
                
                all_frames.append(df)

    if not all_frames:
        sys.exit("[-] No flows were extracted.")

    # Combine, rename, and save
    final_df = pd.concat(all_frames, ignore_index=True)
    final_df = apply_rename(final_df, args.rename)
    
    print(f"\n[+] Processing complete.")
    print(final_df["Label"].value_counts())
    final_df.to_csv(args.out, index=False)
    print(f"[*] Final CSV saved to: {args.out}")

if __name__ == "__main__":
    main()