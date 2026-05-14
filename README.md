# Adaptive Intrusion Detection System (IDS-ML)

A Machine Learning-based Intrusion Detection System built on the **CIC-IDS2017** feature set. The project provides a full pipeline: generating attack traffic in a virtual environment, converting PCAPs to labeled flow data, training an XGBoost classifier, and using SHAP/LIME explainability to reduce the feature set without sacrificing accuracy.

**Source Dataset:** [UNB CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)  
**Course:** CPRE 5600 — Network Architecture and Security

---

## Repository Structure

```
IDS-ML/
├── data/                           # (Gitignored)
│   ├── dataset/                    # CIC-IDS2017 ISCX CSVs
│   ├── captures/                   # Raw PCAPs from VM + attack_ground_truth.csv
│   ├── flows.csv                   # VM flows (pcap → labeled)
│   └── cic_flows.csv               # CIC dataset aligned to model features
├── docs/
│   ├── CPRE 5600 Final Presentation.pptx
│   └── IJET-22797.pdf
├── models/
│   ├── baseline_xgboost.json           # Trained on full 80-feature CIC set
│   ├── preprocessing_info.pkl          # Feature list, label encoder, scalers
│   ├── retrained_model.json            # Retrained on top-N SHAP/LIME features
│   └── retrained_preprocessing_info.pkl
├── notebooks/
│   ├── baseline_analysis.ipynb         # Step 1 — EDA + initial training
│   ├── inference.ipynb                 # Step 2 — Evaluate on VM traffic
│   ├── lime_shap_analysis.ipynb        # Step 3 — Feature explainability & drift
│   └── feature_retrain.ipynb           # Step 4 — Retrain on top features
├── output/                         # (Gitignored) Plots and reports
│   ├── lime_shap/
│   └── retrain/
├── src/
│   ├── attacks/
│   │   └── attack.py               # Attack traffic generation
│   └── preprocessing/
│       ├── pcap_to_labeled_flows.py # PCAP → labeled CIC-format CSV
│       ├── build_cic_flows.py       # Combine + align CIC ISCX CSVs
│       └── rename_map.pkl
├── requirements.txt
└── README.md
```

---

## Pipeline

```
CIC-IDS2017 CSVs ──► 1. baseline_analysis ──► baseline_xgboost.json
                                                preprocessing_info.pkl
                              │
VM pcap capture ──► pcap_to_labeled_flows
                              │
                              ▼
                      2. inference ──────────► inference_results.csv
                              │                confusion matrix
                              ▼
                      3. lime_shap_analysis ──► feature_comparison_table.csv
                              │                 SHAP beeswarm plots
                              ▼
                      4. feature_retrain ────► retrained_model.json
                                               baseline vs retrain report
```

---

## Setup

### 1. Environment

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Register Jupyter kernel
python3 -m ipykernel install --user --name=cpre560 --display-name "Python (cpre560)"

# Install CICFlowMeter (requires uv)
uv tool install git+https://github.com/hieulw/cicflowmeter
```

### 2. System dependencies (attacker VM only)

```bash
sudo apt install nmap hydra hping3 slowhttptest python3-scapy python3-requests
```

---

## Generating Attack Traffic

Run `attack.py` from the **attacker VM** as root. Each run appends a time-fenced entry to `attack_ground_truth.csv`, which `pcap_to_labeled_flows.py` uses to assign labels.

```bash
# General usage
sudo python3 src/attacks/attack.py <attack_type> --target <victim_ip> [options]

# Examples
sudo python3 src/attacks/attack.py dos_hulk       --target 192.168.1.10 --duration 60
sudo python3 src/attacks/attack.py ddos_syn        --target 192.168.1.10 --rate 1000 --duration 30
sudo python3 src/attacks/attack.py port_scan       --target 192.168.1.10 --ports 1-1024
sudo python3 src/attacks/attack.py ssh_brute       --target 192.168.1.10 --userlist data/users.txt --passlist data/passwords.txt
sudo python3 src/attacks/attack.py botnet_beacon   --target 192.168.1.10 --port 8080 --duration 300
sudo python3 src/attacks/attack.py benign          --target 192.168.1.10 --duration 120

# Per-attack help
sudo python3 src/attacks/attack.py <attack_type> --help
```

### Supported Attack Types

| Command | CIC-IDS2017 Label | Tool | Notes |
|---|---|---|---|
| `benign` | BENIGN | urllib / ping / DNS | Mixed background traffic |
| `port_scan` | PortScan | nmap | TCP SYN scan |
| `port_scan_udp` | PortScan | nmap | UDP scan |
| `ddos_syn` | DDoS | hping3 | Non-spoofed by default for bidirectional flows |
| `ddos_udp` | DDoS | hping3 | UDP flood |
| `ddos_icmp` | DDoS | hping3 | ICMP flood |
| `dos_hulk` | DoS Hulk | Custom Python | Threaded HTTP GET flood, matches CIC training data |
| `dos_slowloris` | DoS slowloris | slowhttptest | Slow HTTP connection exhaustion |
| `ssh_brute` | SSH-Patator | hydra | Requires `--userlist` and `--passlist` |
| `ftp_brute` | FTP-Patator | hydra | Requires `--userlist` and `--passlist` |
| `web_brute` | Web Attack Brute Force | hydra | HTTP form brute force |
| `botnet_beacon` | Bot | Socket | TCP C2 heartbeat with jitter |

> **Note:** DDoS attacks default to non-spoofed so the victim sends return traffic, producing the bidirectional flow features the model expects. Pass `--spoof` to randomise source IPs, but be aware this degrades model accuracy.

---

## Processing PCAPs

After capturing traffic on the victim VM, convert PCAPs to a labeled CSV:

```bash
# Minimal (uses all defaults)
python3 src/preprocessing/pcap_to_labeled_flows.py

# Full usage
python3 src/preprocessing/pcap_to_labeled_flows.py \
    --pcap data/captures/ \
    --gt   data/captures/attack_ground_truth.csv \
    --rename src/preprocessing/rename_map.pkl \
    --out  data/flows.csv
```

| Argument | Default | Description |
|---|---|---|
| `--pcap` | `data/captures/` | PCAP file(s) or directory |
| `--gt` | `data/captures/attack_ground_truth.csv` | Ground truth from `attack.py` |
| `--rename` | `src/preprocessing/rename_map.pkl` | Column rename map |
| `--out` | `data/flows.csv` | Output labeled CSV |
| `--label` | — | Force all flows to a single label (skips `--gt`) |

To combine and align the raw CIC-IDS2017 ISCX CSVs into a single file:

```bash
python3 src/preprocessing/build_cic_flows.py \
    --cic_dir data/dataset \
    --out     data/cic_flows.csv \
    --sample  5000          # optional: cap rows per class
```

---

## Running the Notebooks

Run Jupyter from the project root and select the **Python (cpre560)** kernel. Each notebook auto-corrects its working directory if launched from inside `notebooks/`.

```bash
jupyter lab
```

| # | Notebook | Required Inputs | Key Outputs |
|---|---|---|---|
| 1 | `baseline_analysis.ipynb` | `data/dataset/*.csv` | `models/baseline_xgboost.json`, `preprocessing_info.pkl` |
| 2 | `inference.ipynb` | baseline model, `data/flows.csv` | confusion matrix, confidence distributions |
| 3 | `lime_shap_analysis.ipynb` | baseline model, `data/flows.csv`, `data/cic_flows.csv` | `output/lime_shap/feature_comparison_table.csv`, SHAP beeswarm plots |
| 4 | `feature_retrain.ipynb` | baseline model, feature comparison table | `models/retrained_model.json`, `output/retrain/` |

### Notebook Details

**1. baseline_analysis.ipynb** — EDA on CIC-IDS2017, SMOTE oversampling for minority classes, trains XGBoost on a 10% stratified sample of the 2.8M-row dataset.

**2. inference.ipynb** — Loads `flows.csv`, applies `rename_map.pkl` and `preprocessing_info.pkl` to align features, generates a confusion matrix and per-class F1 scores, and plots confidence distributions to identify which attacks the model is uncertain about.

**3. lime_shap_analysis.ipynb** — Uses SHAP (TreeExplainer, global) and LIME (local, per false positive) on both CIC and VM data. Runs Optuna to tune hyperparameters for VM-specific traffic. Produces a composite feature ranking and identifies "domain gap" features — those that are predictive in CIC data but unreliable on real VM traffic.

**4. feature_retrain.ipynb** — Retrains XGBoost on the top-N features from the SHAP/LIME composite ranking, benchmarks against the baseline on the same held-out test set, and optionally evaluates on VM traffic.

### Using the Retrained Model

To run inference with the leaner retrained model, update these two variables at the top of `inference.ipynb`:

```python
MODEL_PATH     = "models/retrained_model.json"
ARTIFACTS_PATH = "models/retrained_preprocessing_info.pkl"
```

---

## Feature Retrain Configuration

Key parameters in `feature_retrain.ipynb` (Cell 2):

| Parameter | Default | Description |
|---|---|---|
| `TOP_N_FEATURES` | `20` | Features to keep — try 20, 30, or 40 |
| `RANK_BY` | `'Composite'` | Ranking column: `Composite`, `CIC_SHAP`, `VM_SHAP`, `CIC_LIME`, `VM_LIME` |
| `SAMPLE_FRACTION` | `0.10` | Fraction of CIC data used for training (matches baseline) |
| `MIN_SMOTE` | `50` | Classes below this count use class weighting instead of SMOTE |

---

## Retrain Outputs

After running `feature_retrain.ipynb`, `output/retrain/` contains:

| File | Description |
|---|---|
| `selected_features.png` | Bar chart of top-N features and composite scores |
| `confusion_matrix_comparison.png` | Side-by-side: baseline vs retrained |
| `f1_delta.png` | Per-class F1 change (retrained − baseline) |
| `model_comparison.csv` | Accuracy, macro F1, precision, recall, inference speed |
| `per_class_comparison.csv` | Full per-class breakdown with delta column |
| `retrain_summary.txt` | Plain-text summary report |

---

## References

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *ICISSP 2018*.
- See `docs/IJET-22797.pdf` for additional methodology references.
