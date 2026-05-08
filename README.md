# Adaptive Intrusion Detection System (IDS-ML)

This project implements a Machine Learning-based Intrusion Detection System focused on the **CIC-IDS2017** feature set. It provides a full pipeline for generating attack traffic in a virtual environment, processing packet captures (PCAPs) into labeled flow data, and evaluating models using a "Lean" version of the original CIC-IDS research notebooks.

## Repository Structure

```text
.
├── docs/               # Setup instructions and documentation
├── models/             # Pre-trained models and preprocessing artifacts
│   ├── baseline_xgboost.json  # Trained XGBoost model
│   └── preprocessing_info.pkl # Scalers/encoders for the pipeline
├── notebooks/          # Jupyter notebooks for training and evaluation
│   ├── LeanNotebook.ipynb     # Main evaluation/EDA notebook
│   └── LeanNotebookWithGT.ipynb
├── src/                # Source code
│   ├── attacks/        # Traffic generation scripts
│   │   └── attack.py   # Master attack script (SYN, Hulk, Slowloris, etc.)
│   ├── preprocessing/  # Data conversion and labeling
│   │   ├── pcap_to_labeled_flows.py
│   │   └── rename_map.pkl
├── data/               # (Gitignored) Raw PCAPs and generated CSVs
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

Use the `attack.py` script to generate specific classes of traffic against a target VM. This script automatically logs "time fences" to `attack_ground_truth.csv`.

```bash
sudo python3 src/attacks/attack.py dos_hulk --target 192.168.1.50 --duration 60

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

Open `notebooks/LeanNotebook.ipynb`, select the **Python (cpre560)** kernel, and load `data/flows.csv` to see how the model performs against your custom captured traffic.

## 🛠 Supported Attack Types

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