# Offline & Air-Gapped Deployment Guide

**Project**: Cryptographic Attribution and Auditable Decryption Provenance for Multi-Recipient Encrypted Document Distribution
**Problem Statement**: SIH PS 26237  

---

## 1. Local and Offline Operation

The web console binds to `127.0.0.1` and makes no cloud/API calls. It can run without network access after dependencies are installed. Loopback binding alone does not establish that the host or surrounding network is air-gapped.
- **No Cloud KMS**: Keys generated and stored in local filesystem keystore (`data/keystore/` or `demo/keystores/`).
- **No Cloud Databases**: State persisted in deterministic local JSON ledgers (`data/ledger/blockchain.json`).
- **No Public Blockchain**: Self-contained 5-validator permissioned ledger running locally.
- **Offline Cryptography**: ML-KEM, ML-DSA, SHA3-256, and AES-GCM operations use locally installed libraries. Prepare and transfer a wheelhouse when installing on a disconnected machine.

---

## 2. Pre-Requisites & System Requirements

- **Python**: Python 3.10+ (tested and verified on Python 3.14.3 with `cryptography 50.0.1`).
- **Operating System**: Cross-platform (Windows, Linux, macOS).
- **Core Libraries**:
  - `cryptography >= 50.0.1` (provides native NIST FIPS 203 ML-KEM and FIPS 204 ML-DSA)
  - `numpy >= 2.0.0`
  - `opencv-python >= 4.12.0`
  - `pillow >= 10.0.0`
  - `rich >= 13.0.0`

---

## 3. Offline Installation Instructions

### Step 1: Pre-download Wheels on an Internet-Connected Machine
On a machine with internet access, pre-download all wheels into a local directory:
```bash
mkdir wheels
pip download -r requirements.txt -d wheels/
```

### Step 2: Transfer to Air-Gapped Machine
Transfer the project directory and the `wheels/` folder via secure removable media (e.g. encrypted USB drive).

### Step 3: Install Wheels Offline
On the target air-gapped machine:
```bash
pip install --no-index --find-links=wheels/ -r requirements.txt
```

---

## 4. Verification in Air-Gapped Environment

Run the automated test suite to confirm complete offline functionality:
```bash
# Verify all 43 automated tests
python -m unittest discover -s tests -v

# Run the watermark robustness benchmark
python benchmarks/run_watermark_benchmark.py

# Run the turnkey end-to-end demo
python demo/run_demo.py
```
