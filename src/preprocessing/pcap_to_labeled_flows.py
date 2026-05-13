#!/usr/bin/env python3
"""
pcap_to_labeled_flows.py
========================
Converts .pcap files or directories into a single labeled flows CSV.
Optimized for the IDS-ML repository structure.

Minimal usage (all defaults assumed):
  python3 src/preprocessing/pcap_to_labeled_flows.py

Full usage:
  python3 src/preprocessing/pcap_to_labeled_flows.py \
      --pcap data/captures/ \
      --gt data/captures/attack_ground_truth.csv \
      --rename src/preprocessing/rename_map.pkl \
      --out data/flows.csv
"""

import argparse
import glob
import os
import pickle
import subprocess
import sys
import tempfile

import numpy as np
import pandas as pd

# ── Defaults (all relative to project root) ───────────────────────────────────
DEFAULT_PCAP_DIR  = "data/captures"
DEFAULT_GT        = "data/captures/attack_ground_truth.csv"
DEFAULT_RENAME    = "src/preprocessing/rename_map.pkl"
DEFAULT_OUT       = "data/flows.csv"

# ── Label map (matches attack.py attack_type values) ─────────────────────────
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
    """Invokes cicflowmeter via uv tool or shell fallback."""
    cmds = [
        ["uv", "tool", "run", "cicflowmeter", "-f", pcap_path, "-c", out_csv],
        ["cicflowmeter", "-f", pcap_path, "-c", out_csv],
    ]
    for cmd in cmds:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0 or (os.path.isfile(out_csv) and os.path.getsize(out_csv) > 0):
                return
        except FileNotFoundError:
            continue
    sys.exit("[-] CICFlowMeter not found. Install with: uv tool install git+https://github.com/hieulw/cicflowmeter")


def load_ground_truth(gt_path: str) -> pd.DataFrame:
    """Loads and cleans attack_ground_truth.csv produced by attack.py."""
    gt = pd.read_csv(gt_path)
    
    gt.columns = gt.columns.str.strip()

    gt = gt.dropna(subset=["attack_type"])
    gt["attack_type"] = gt["attack_type"].astype(str)

    gt["label"] = gt["attack_type"].str.strip().str.lower().map(LABEL_MAP)

    unmapped = gt[gt["label"].isna()]["attack_type"].unique()
    if len(unmapped):
        print(f"[!] No label mapping for: {list(unmapped)} — using raw name.")
        gt["label"] = gt["label"].fillna(gt["attack_type"])

    gt["start_time"] = pd.to_numeric(gt["start_time"])
    gt["end_time"]   = pd.to_numeric(gt["end_time"])
    # Ensure every attack window is at least 60 seconds wide
    MIN_WINDOW = 60
    narrow = (gt["end_time"] - gt["start_time"]) < MIN_WINDOW
    gt.loc[narrow, "start_time"] -= MIN_WINDOW / 2
    gt.loc[narrow, "end_time"]   += MIN_WINDOW / 2
    if narrow.any():
        print(f"[!] Widened {narrow.sum()} narrow window(s) to {MIN_WINDOW}s minimum.")
    gt["label"] = gt["label"].str.replace("\ufffd ", "", regex=False)
    return gt


def assign_labels(df: pd.DataFrame, gt: pd.DataFrame) -> pd.DataFrame:
    """Matches flow timestamps against ground truth attack windows."""
    ts_col = next(
        (c for c in df.columns if c.lower() in ("timestamp", "ts", "flow_start_time")),
        None,
    )
    if ts_col is None:
        df["Label"] = "BENIGN"
        return df

    ts = pd.to_numeric(df[ts_col], errors="coerce")
    if ts.isna().all():
        # CICFlowMeter wrote human-readable datetimes — convert to epoch
        ts = pd.to_datetime(df[ts_col], errors="coerce").dt.tz_localize("America/Chicago").astype("int64") / 1e6
    elif ts.median() > 2e12:
        ts = ts / 1e6  # microseconds → seconds

    labels = pd.Series(["BENIGN"] * len(df), index=df.index, dtype=str)
    for _, row in gt.iterrows():
        mask = (ts >= row["start_time"]) & (ts <= row["end_time"])
        labels[mask] = row["label"]

    df["Label"] = labels
    return df


def apply_rename(df: pd.DataFrame, rename_pkl: str) -> pd.DataFrame:
    """Renames raw CICFlowMeter columns to the model's expected names."""
    with open(rename_pkl, "rb") as fh:
        rename_map = pickle.load(fh)
    df.rename(columns=rename_map, inplace=True)
    if "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    return df


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert PCAPs to a labeled flows CSV for the IDS-ML pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--pcap", nargs="+", default=[DEFAULT_PCAP_DIR],
        help="One or more PCAP files or directories to process.",
    )
    parser.add_argument(
        "--gt", default=DEFAULT_GT,
        help="Path to attack_ground_truth.csv (from attack.py).",
    )
    parser.add_argument(
        "--label",
        help="Force every flow to this label, ignoring --gt.",
    )
    parser.add_argument(
        "--rename", default=DEFAULT_RENAME,
        help="Path to rename_map.pkl.",
    )
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help="Output CSV path.",
    )
    args = parser.parse_args()

    # Validate required files
    if not os.path.exists(args.rename):
        sys.exit(f"[-] rename_map.pkl not found at '{args.rename}'. "
                 f"Run from project root or pass --rename.")

    if not args.label and not os.path.exists(args.gt):
        print(f"[!] Ground truth not found at '{args.gt}'. All flows will be labelled BENIGN.")
        gt = None
    else:
        gt = load_ground_truth(args.gt) if not args.label else None

    # Expand directories into pcap file list
    all_pcaps = []
    for p in args.pcap:
        if os.path.isdir(p):
            all_pcaps.extend(sorted(glob.glob(os.path.join(p, "*.pcap*"))))
        elif os.path.isfile(p):
            all_pcaps.append(p)
        else:
            print(f"[!] Path not found, skipping: {p}")

    if not all_pcaps:
        sys.exit(f"[-] No PCAP files found. Check --pcap path (default: {DEFAULT_PCAP_DIR})")

    print(f"[*] Processing {len(all_pcaps)} PCAP file(s) → {args.out}")

    all_frames = []
    with tempfile.TemporaryDirectory() as tmp:
        for pcap in all_pcaps:
            raw_csv = os.path.join(tmp, f"{os.path.basename(pcap)}.csv")
            print(f"  → {os.path.basename(pcap)}", end=" ... ", flush=True)
            run_cicflowmeter(pcap, raw_csv)

            if not os.path.exists(raw_csv):
                print("no output, skipping.")
                continue

            df = pd.read_csv(raw_csv)
            df.columns = df.columns.str.strip()
            df.replace([np.inf, -np.inf], np.nan, inplace=True)

            if args.label:
                df["Label"] = args.label
            elif gt is not None:
                df = assign_labels(df, gt)
            else:
                df["Label"] = "BENIGN"

            print(f"{len(df):,} flows")
            all_frames.append(df)

    if not all_frames:
        sys.exit("[-] No flows were extracted from any PCAP.")

    final_df = pd.concat(all_frames, ignore_index=True)
    final_df  = apply_rename(final_df, args.rename)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    final_df.to_csv(args.out, index=False)

    print(f"\n[+] Saved {len(final_df):,} flows → {args.out}")
    print("[*] Label distribution:")
    print(final_df["Label"].value_counts().to_string())


if __name__ == "__main__":
    main()
