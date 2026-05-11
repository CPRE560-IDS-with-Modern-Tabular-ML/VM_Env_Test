# Adaptive Intrusion Detection System (IDS-ML)

This project implements a Machine Learning-based Intrusion Detection System focused on the **CIC-IDS2017** feature set. It provides a full pipeline for generating attack traffic in a virtual environment, processing packet captures (PCAPs) into labeled flow data, and performing advanced model explainability and optimization.

**Source Dataset:** [UNB CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

## Repository Structure

```text
.
├── data/                           # (Gitignored) Raw PCAPs, CSVs, and Wordlists
├── docs/                           # Setup instructions and documentation
├── models/                         # Pre-trained models and preprocessing artifacts
│   ├── baseline_xgboost.json       # The core XGBoost classifier
│   └── preprocessing_info.pkl      # Feature lists and scaling metadata
├── notebooks/                      # Analysis & Research Pipeline
│   ├── baseline_analysis.ipynb     # Dataset EDA & initial training
│   ├── inference.ipynb             # Model evaluation on VM traffic
│   └── lime_shap_analysis.ipynb    # Feature drift & explainability
├── output/                         # (Gitignored) Plots, SHAP/LIME artifacts
├── src/                            # Source code
│   ├── attacks/                    # Traffic generation (attack.py)
│   └── preprocessing/              # PCAP processing (pcap_to_labeled_flows.py)
├── README.md
├── requirements.txt
└── .gitignore
```

## Quick Start

### 1. Environment Setup

Create and activate your virtual environment, then install dependencies:

```bash
# Register the kernel for Jupyter
python3 -m ipykernel install --user --name=cpre560 --display-name "Python (cpre560)"

# Install packages
pip install -r requirements.txt

# Install CICFlowMeter (requires 'uv')
uv tool install git+[https://github.com/hieulw/cicflowmeter](https://github.com/hieulw/cicflowmeter)
```

### 2. Generate Attack Traffic

```bash
# Generate attack on Attacker VM
sudo python3 src/attacks/attack.py dos_hulk --target <victim_ip>

# Convert PCAP to Labeled CSV
python3 src/preprocessing/pcap_to_labeled_flows.py \
    --pcap data/captures/ \
    --gt attack_ground_truth.csv \
    --rename src/preprocessing/rename_map.pkl \
    --out data/vm_flows.csv
```

### 3. Process and Label Flows

Convert your captured `.pcap` files into a labeled CSV using the ground truth windows:

```bash
python3 src/preprocessing/pcap_to_labeled_flows.py \
    --pcap data/pcaps/ \
    --gt attack_ground_truth.csv \
    --rename src/preprocessing/rename_map.pkl \
    --out data/flows.csv

```

### 4. Evaluate in Jupyter

Open `notebooks/inference.ipynb`, select the **Python (cpre560)** kernel, and load `data/flows.csv` to see how the model performs against your custom captured traffic.

## Notebooks Overview

1. Baseline Analysis (baseline_analysis.ipynb)

Goal: Understand the primary CIC-IDS-2017 dataset and establish a performance ceiling.

* Exploratory Data Analysis (EDA): Identifies class imbalances and feature distributions.

* Preprocessing: Handles minority class oversampling (SMOTE) and removes undersized classes.

* Training: Trains the baseline XGBoost model on a representative subset (10%) of the 2.8M rows.

2. Network Flow Inference (inference.ipynb)

Goal: Test the "Adaptive" capability of the model against real-world VM traffic.

* Pipeline: Loads processed CSVs from your VM, applies the rename_map.pkl and preprocessing_info.pkl to align features.

* Evaluation: Runs inference and generates a confusion matrix vs. the attack_ground_truth.csv labels.

* Visualization: Plots confidence distributions to identify which attacks the model is "unsure" about.

3. LIME/SHAP/Optuna Analysis (lime_shap_analysis.ipynb)

Goal: Explain the "Domain Gap" between the lab dataset and real VM traffic.

* Optuna: Automatically tunes XGBoost hyperparameters specifically for your VM's network characteristics.

* SHAP (Global): Uses TreeExplainer to rank which features (e.g., Destination Port vs Flow IAT) drive the model's decisions on both datasets.

* LIME (Local): Provides instance-level explanations for specific False Positives to see why the model misclassified a flow.

* Drift Analysis: Identifies "Domain-Gap" features—indicators that work in the CIC dataset but fail in the real world

## Supported Attack Types

| Attack Type | Label (CIC-IDS2017) | Tool Used |
| --- | --- | --- |
| Benign Traffic | BENIGN | urllib/ping/dns |
| SYN Flood | DDoS | hping3 |
| HTTP Hulk | DoS Hulk | Custom Python (Threaded) |
| Slowloris | DoS slowloris | slowhttptest |
| Port Scan | PortScan | nmap |
| Brute Force | SSH-Patator / FTP-Patator | hydra |
| Botnet | Bot | Socket-based Beaconing |

## Project Context

Developed for **CPRE 5600: Network Architecture and Security**. The project aims to create an "Adaptive IDS" where the model can be fine-tuned on environment-specific traffic while maintaining high detection accuracy on the standard CIC-IDS2017 attack profiles.

---

**Note:** For detailed implementation details regarding feature importance and XGBoost hyper-parameters, refer to the documents in `/docs` and the original project Midterm Paper.