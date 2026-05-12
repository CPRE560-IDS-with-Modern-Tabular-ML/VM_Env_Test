#!/usr/bin/env python3
"""
build_cic_flows.py
==================
Combines the raw CIC-IDS2017 ISCX CSVs into a single cic_flows.csv
aligned to the model's feature_columns and rename_map.

Minimal usage (all defaults assumed, run from project root):
  python3 src/preprocessing/build_cic_flows.py

Full usage:
  python3 src/preprocessing/build_cic_flows.py \
      --cic_dir data/dataset \
      --pkl     models/preprocessing_info.pkl \
      --rename  src/preprocessing/rename_map.pkl \
      --out     data/cic_flows.csv \
      --sample  5000
"""

import argparse
import glob
import os
import pickle
import sys

import numpy as np
import pandas as pd

# ── Defaults (all relative to project root) ───────────────────────────────────
DEFAULT_CIC_DIR = "data/dataset"
DEFAULT_PKL     = "models/preprocessing_info.pkl"
DEFAULT_RENAME  = "src/preprocessing/rename_map.pkl"
DEFAULT_OUT     = "data/cic_flows.csv"

# ── Label normalisation map ───────────────────────────────────────────────────
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
    # Fuzzy fallbacks
    if "brute" in lower:                         return "Web Attack Brute Force"
    if "sql" in lower:                           return "Web Attack Sql Injection"
    if "xss" in lower:                           return "Web Attack XSS"
    if "goldeneye" in lower:                     return "DoS GoldenEye"
    if "hulk" in lower:                          return "DoS Hulk"
    if "slowhttp" in lower:                      return "DoS Slowhttptest"
    if "slowloris" in lower or "loris" in lower: return "DoS slowloris"
    if "ddos" in lower:                          return "DDoS"
    if "benign" in lower:                        return "BENIGN"
    if "bot" in lower:                           return "Bot"
    if "infiltr" in lower:                       return "Infiltration"
    if "heartbleed" in lower:                    return "Heartbleed"
    if "portscan" in lower or "port scan" in lower: return "PortScan"
    if "ftp" in lower:                           return "FTP-Patator"
    if "ssh" in lower:                           return "SSH-Patator"
    print(f"  [!] Unknown label: '{raw}' — keeping as-is")
    return raw


def load_iscx_csv(path: str, rename_map: dict) -> pd.DataFrame:
    """Load one ISCX CSV, clean it, apply rename map, normalise labels."""
    print(f"  {os.path.basename(path):65s}", end=" ... ", flush=True)
    try:
        df = pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(path, low_memory=False, encoding="latin-1")

    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.rename(columns=rename_map, inplace=True)

    if "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]

    label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
    if label_col:
        df[label_col] = df[label_col].map(normalise_label)
        df.rename(columns={label_col: "Label"}, inplace=True)
    else:
        print(f"\n  [!] No Label column found — defaulting to BENIGN")
        df["Label"] = "BENIGN"

    print(f"{len(df):,} rows")
    return df


def main():
    parser = argparse.ArgumentParser(
        description="Combine CIC-IDS2017 ISCX CSVs into a single cic_flows.csv.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--cic_dir", default=DEFAULT_CIC_DIR,
        help="Directory containing *_ISCX.csv files.",
    )
    parser.add_argument(
        "--pkl", default=DEFAULT_PKL,
        help="Path to preprocessing_info.pkl.",
    )
    parser.add_argument(
        "--rename", default=DEFAULT_RENAME,
        help="Path to rename_map.pkl.",
    )
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help="Output CSV path.",
    )
    parser.add_argument(
        "--sample", type=int, default=None,
        help="Sample up to N rows per class (e.g. 5000). Omit to keep all rows.",
    )
    args = parser.parse_args()

    # Validate required paths before doing any work
    missing = [(label, path) for label, path in [
        ("--cic_dir", args.cic_dir),
        ("--pkl",     args.pkl),
        ("--rename",  args.rename),
    ] if not os.path.exists(path)]

    if missing:
        msgs = "\n".join(f"  {lbl}: '{p}'" for lbl, p in missing)
        sys.exit(
            f"[-] Required path(s) not found:\n{msgs}\n"
            f"    Make sure you are running from the project root."
        )

    # Load shared artifacts
    with open(args.pkl, "rb") as f:
        artifacts = pickle.load(f)
    feature_cols = artifacts["feature_columns"]
    print(f"[*] preprocessing_info.pkl — {len(feature_cols)} feature columns")

    with open(args.rename, "rb") as f:
        rename_map = pickle.load(f)
    print(f"[*] rename_map.pkl         — {len(rename_map)} column mappings")

    # Find CSVs
    csv_files = sorted(glob.glob(os.path.join(args.cic_dir, "*.csv")))
    if not csv_files:
        sys.exit(f"[-] No CSV files found in '{args.cic_dir}'")

    print(f"\n[*] Found {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"    {os.path.basename(f):65s} {os.path.getsize(f)/1024**2:6.1f} MB")

    # Load and combine
    frames = []
    print()
    for path in csv_files:
        try:
            frames.append(load_iscx_csv(path, rename_map))
        except Exception as e:
            print(f"  [!] Failed to load {path}: {e}")

    if not frames:
        sys.exit("[-] No data loaded successfully.")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[*] Combined shape: {combined.shape}")
    print("[*] Label distribution (before sampling):")
    print(combined["Label"].value_counts().to_string())

    # Optional per-class sampling
    if args.sample:
        print(f"\n[*] Sampling up to {args.sample} rows per class ...")
        sampled = [
            grp.sample(n=min(len(grp), args.sample), random_state=42)
            for _, grp in combined.groupby("Label")
        ]
        combined = pd.concat(sampled, ignore_index=True)
        print(f"[*] Sampled shape: {combined.shape}")

    # Align to model feature columns
    print("\n[*] Aligning to model feature_columns ...")
    non_feature = {
        "Label", "label", "src_ip", "dst_ip", "Src IP", "Dst IP",
        "Source IP", "Destination IP", "Flow ID", "flow_id",
        "timestamp", "Timestamp", "ts",
    }
    model_cols = [c for c in feature_cols if c not in non_feature]

    added = []
    for col in model_cols:
        if col not in combined.columns:
            combined[col] = 0.0
            added.append(col)
    if added:
        print(f"  [!] Added {len(added)} missing columns as 0: {added[:5]}{'...' if len(added) > 5 else ''}")

    keep_cols = [c for c in model_cols if c in combined.columns] + ["Label"]
    combined  = combined[keep_cols]

    # Save
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    combined.to_csv(args.out, index=False)

    print(f"\n[+] Saved {len(combined):,} rows × {combined.shape[1]} columns → {args.out}")
    print("\n[*] Final label distribution:")
    print(combined["Label"].value_counts().to_string())
    print("\nDone — run notebooks/lime_shap_analysis.ipynb to continue.")


if __name__ == "__main__":
    main()
