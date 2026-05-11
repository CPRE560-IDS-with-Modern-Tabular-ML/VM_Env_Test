#!/usr/bin/env python3
"""
build_cic_flows.py
==================
Combines the 8 raw CIC-IDS2017 ISCX CSVs into a single cic_flows.csv
aligned to your model's feature_columns and rename_map.

Run from project root (no arguments needed — defaults match repo structure):
  python3 src/preprocessing/build_cic_flows.py

Or override any path:
  python3 src/preprocessing/build_cic_flows.py --sample 5000
"""

import argparse
import glob
import os
import pickle
import sys

import numpy as np
import pandas as pd

# ── Label normalisation ────────────────────────────────────────────────────────
LABEL_MAP = {
    "benign":                        "BENIGN",
    "BENIGN":                        "BENIGN",
    "ddos":                          "DDoS",
    "DDoS":                          "DDoS",
    "dos goldeneye":                 "DoS GoldenEye",
    "DoS GoldenEye":                 "DoS GoldenEye",
    "dos hulk":                      "DoS Hulk",
    "DoS Hulk":                      "DoS Hulk",
    "dos slowhttptest":              "DoS Slowhttptest",
    "DoS Slowhttptest":              "DoS Slowhttptest",
    "dos slowloris":                 "DoS slowloris",
    "DoS slowloris":                 "DoS slowloris",
    "dos loris":                     "DoS slowloris",
    "ftp-patator":                   "FTP-Patator",
    "FTP-Patator":                   "FTP-Patator",
    "ssh-patator":                   "SSH-Patator",
    "SSH-Patator":                   "SSH-Patator",
    "web attack  brute force":       "Web Attack Brute Force",
    "web attack brute force":        "Web Attack Brute Force",
    "Web Attack \x96 Brute Force":   "Web Attack Brute Force",
    "web attack  sql injection":     "Web Attack Sql Injection",
    "web attack sql injection":      "Web Attack Sql Injection",
    "Web Attack \x96 Sql Injection": "Web Attack Sql Injection",
    "web attack  xss":               "Web Attack XSS",
    "web attack xss":                "Web Attack XSS",
    "Web Attack \x96 XSS":          "Web Attack XSS",
    "bot":                           "Bot",
    "Bot":                           "Bot",
    "infiltration":                  "Infiltration",
    "Infiltration":                  "Infiltration",
    "heartbleed":                    "Heartbleed",
    "Heartbleed":                    "Heartbleed",
    "portscan":                      "PortScan",
    "PortScan":                      "PortScan",
}


def normalise_label(raw: str) -> str:
    raw = str(raw).strip()
    if raw in LABEL_MAP:
        return LABEL_MAP[raw]
    lower = raw.lower()
    for k, v in LABEL_MAP.items():
        if k.lower() == lower:
            return v
    if "brute" in lower:      return "Web Attack Brute Force"
    if "sql" in lower:        return "Web Attack Sql Injection"
    if "xss" in lower:        return "Web Attack XSS"
    if "goldeneye" in lower:  return "DoS GoldenEye"
    if "hulk" in lower:       return "DoS Hulk"
    if "slowhttp" in lower:   return "DoS Slowhttptest"
    if "slowloris" in lower or "loris" in lower: return "DoS slowloris"
    if "ddos" in lower:       return "DDoS"
    if "benign" in lower:     return "BENIGN"
    if "bot" in lower:        return "Bot"
    if "infiltr" in lower:    return "Infiltration"
    if "heartbleed" in lower: return "Heartbleed"
    if "portscan" in lower or "port scan" in lower: return "PortScan"
    if "ftp" in lower:        return "FTP-Patator"
    if "ssh" in lower:        return "SSH-Patator"
    print(f"  [!] Unknown label: '{raw}' — keeping as-is")
    return raw


def load_iscx_csv(path: str, rename_map: dict) -> pd.DataFrame:
    """Load one ISCX CSV, clean it, apply rename map, normalise labels."""
    print(f"  Loading {os.path.basename(path)} ...", end=" ", flush=True)
    try:
        df = pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(path, low_memory=False, encoding="latin-1")

    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.rename(columns=rename_map, inplace=True)

    # CICIDS2017 duplicate header fix
    if "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]

    label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
    if label_col:
        df[label_col] = df[label_col].map(normalise_label)
        df.rename(columns={label_col: "Label"}, inplace=True)
    else:
        print(f"\n  [!] Warning: no Label column in {path}")
        df["Label"] = "BENIGN"

    print(f"{len(df):,} rows  |  {df['Label'].value_counts().to_dict()}")
    return df


def main():
    parser = argparse.ArgumentParser(description="Combine CIC-IDS2017 ISCX CSVs")

    # Defaults match actual repo structure: data/dataset/ for ISCX files
    parser.add_argument("--cic_dir", default="data/dataset",
                        help="Dir with *_ISCX.csv files (default: data/dataset)")
    parser.add_argument("--pkl",     default="models/preprocessing_info.pkl",
                        help="Path to preprocessing_info.pkl")
    parser.add_argument("--rename",  default="src/preprocessing/rename_map.pkl",
                        help="Path to rename_map.pkl")
    parser.add_argument("--out",     default="data/cic_flows.csv",
                        help="Output path (default: data/cic_flows.csv)")
    parser.add_argument("--sample",  type=int, default=None,
                        help="Sample N rows per class (recommended: 5000)")
    args = parser.parse_args()

    # Validate paths before doing any work
    for label, path in [("--cic_dir", args.cic_dir),
                         ("--pkl",     args.pkl),
                         ("--rename",  args.rename)]:
        if not os.path.exists(path):
            sys.exit(
                f"[-] {label} not found: '{path}'\n"
                f"    Make sure you're running from the project root:\n"
                f"    cd ~/Spring\\ 2026/cpre560/IDS-ML"
            )

    # Load artifacts
    with open(args.pkl, "rb") as f:
        artifacts = pickle.load(f)
    feature_cols = artifacts["feature_columns"]
    print(f"[*] Loaded pkl  — {len(feature_cols)} feature columns")

    with open(args.rename, "rb") as f:
        rename_map = pickle.load(f)
    print(f"[*] Loaded rename_map — {len(rename_map)} column mappings")

    # Find CSVs
    csv_files = sorted(set(glob.glob(os.path.join(args.cic_dir, "*.csv"))))
    if not csv_files:
        sys.exit(f"[-] No CSV files found in '{args.cic_dir}'")

    print(f"\n[*] Found {len(csv_files)} CSV files:")
    for f in csv_files:
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"    {os.path.basename(f):65s} {size_mb:6.1f} MB")

    # Load and combine
    frames = []
    for path in csv_files:
        try:
            df = load_iscx_csv(path, rename_map)
            frames.append(df)
        except Exception as e:
            print(f"  [!] Failed to load {path}: {e}")

    if not frames:
        sys.exit("[-] No data loaded.")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[*] Combined shape: {combined.shape}")
    print("[*] Label distribution (before sampling):")
    print(combined["Label"].value_counts().to_string())

    # Optional per-class sampling
    if args.sample:
            print(f"\n[*] Sampling up to {args.sample} rows per class ...")
            
            # Safe sampling for Pandas 3.x
            sampled_groups = []
            for label, group in combined.groupby("Label"):
                n_samples = min(len(group), args.sample)
                sampled_groups.append(group.sample(n=n_samples, random_state=42))
                
            combined = pd.concat(sampled_groups, ignore_index=True)
            print(f"[*] Sampled shape: {combined.shape}")

    # Align to model feature columns, drop identifier/target cols
    print("\n[*] Aligning to model feature_columns ...")
    non_feature = {
        "Label", "label", "src_ip", "dst_ip", "Src IP", "Dst IP",
        "Source IP", "Destination IP", "Flow ID", "flow_id",
        "timestamp", "Timestamp", "ts",
    }
    model_cols = [c for c in feature_cols if c not in non_feature]

    for col in model_cols:
        if col not in combined.columns:
            print(f"  [!] Missing column '{col}' — filling with 0")
            combined[col] = 0.0

    keep_cols = [c for c in model_cols if c in combined.columns] + ["Label"]
    combined  = combined[keep_cols]

    # Save
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    combined.to_csv(args.out, index=False)

    print(f"\n[+] Saved → {args.out}")
    print(f"    {len(combined):,} rows × {combined.shape[1]} columns")
    print("\n[*] Final label distribution:")
    print(combined["Label"].value_counts().to_string())
    print("\nDone — open notebooks/lime_shap_analysis.ipynb to run the analysis")


if __name__ == "__main__":
    main()