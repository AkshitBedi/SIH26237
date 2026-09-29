# Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution

**SIH Problem Statement 26237** | **National-Level Working Prototype**  
**Repository**: [AkshitBedi/SIH26237](https://github.com/AkshitBedi/SIH26237)  
**Authors**: Team AkshitBedi  

---

## 1. Executive Summary

This repository contains a working prototype for **SIH Problem Statement 26237**: an offline-capable cryptographic pipeline linking encrypted multi-recipient document distribution to recipient-specific decryption provenance and invisible forensic watermark attribution. The ledger is designed to be tamper-evident; the prototype does not claim physical immutability.

```
ENCRYPT (ML-KEM-768 + AES-256-GCM)
  ↓
DISTRIBUTE (Single ciphertext, multi-recipient key capsules)
  ↓
AUTHENTICATE (ML-DSA-65 Challenge-Response)
  ↓
DECRYPT SESSION PREPARATION (Unique session ID + watermark ID)
  ↓
SIGN PROVENANCE RECORD (Recipient ML-DSA-65 signature on canonical JSON)
  ↓
COMMIT-BEFORE-RELEASE (4-of-5 Permissioned Validator Quorum)
  ↓
EMBED WATERMARK (Transform-domain DWT/DCT + Barker Sync + ECC)
  ↓
RELEASE WATERMARKED DOCUMENT
  ↓
SIMULATE LEAK (Screenshot / JPEG Q70 / Crop / Blur)
  ↓
ONE-COMMAND FORENSIC TRACE (`trace <leaked-file>`)
  ↓
VERIFY MERKLE PROOF, PQC SIGNATURES & VALIDATOR QUORUM
  ↓
IDENTIFY RECIPIENT & EXPORT VERIFIABLE EVIDENCE BUNDLE
```

---

## 2. Quick Start: One-Command Live Demonstration

Run the complete 8-step interactive CLI demo in one command:
```bash
python demo/run_demo.py
```
Each run gets a new directory under `demo/runs/`; earlier demo artifacts are preserved. The script stops on the first failed command and prints the run directory for inspection.

### Run Automated Security Test Suite (43 Tests)
```bash
python -m unittest discover -s tests -v
```

### Run Watermark Robustness Benchmark
```bash
python benchmarks/run_watermark_benchmark.py
```

---

## 3. Local Web Demonstration

The prototype includes a local web console built with Python Flask and vanilla JavaScript. It binds to `127.0.0.1` and does not call cloud services. The console can run without network access once its Python dependencies are installed; its local-only status is not proof that the host operating system or network is isolated.

### Environment Setup & Start Command

```bash
# 1. Create and activate virtual environment (optional)
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# 2. Install minimum-version dependencies (use a local wheelhouse on an air-gapped machine)
pip install -r requirements.txt

# 3. Start the local security console
python frontend/app.py
```

Then open your browser at:
```
http://127.0.0.1:5000
```

### 60-Second Judge Demo Procedure

For live evaluations, follow this simple walkthrough:

1. **Open Dashboard**: Navigate to `http://127.0.0.1:5000`. Observe the PQC stack and `LOCAL ONLY • LOOPBACK` service indicator.
2. **Select Document**: Confirm `confidential_brief.png` is selected in **SECURE DOCUMENT DISTRIBUTION**.
3. **Select Recipients**: Keep `REC-001`, `REC-002`, and `REC-047` checked.
4. **Encrypt & Distribute**: Click `[ ENCRYPT & DISTRIBUTE ]`. Observe single AES-256-GCM ciphertext creation, ML-KEM-768 key encapsulation, and SHA3-256 document hash.
5. **Decrypt & Commit**: In **CONTROLLED DECRYPTION**, select recipient `REC-047` and click `[ DECRYPT & COMMIT ]`.
6. **Observe Commit-Before-Release**: After the backend operation completes, review the reported sequence: recipient authentication, provenance signing, validator signatures, ledger commit, watermarking, and release. The UI does not claim per-stage live progress.
7. **Show Validator Quorum**: Read the signature count returned by the ledger and note the actual `Session ID` and `Watermark ID`.
8. **Simulate Leak**: In **FORENSIC ATTRIBUTION**, choose an attack (e.g. `Screen Capture / LCD Re-encode` or `JPEG Q70`) and click `[ SIMULATE LEAK ATTACK ]`.
9. **Trace Leak**: Click `[ TRACE LEAK & IDENTIFY RECIPIENT ]`. Watch the automated pipeline extract the watermark, query the ledger, and verify the cryptographic proofs.
10. **Verify Attribution & Evidence**: A green `ATTRIBUTION VERIFIED` banner appears only when the backend reports all required checks passed. Review the actual recipient, signature, Merkle proof, validator quorum, and evidence bundle values.

### Security boundary

Commit-before-release is enforced by the application workflow. A recipient controlling a compromised endpoint could extract plaintext from memory. Variant-Segment Encryption (VSE) is a documented production-hardening concept and is **not implemented** in this prototype.

---

## 4. Cryptographic Stack & Standards

All cryptographic primitives are strictly offline and standardized by NIST:

| Component | Standard | Algorithm | Key / Parameter Details |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | NIST FIPS 203 | **ML-KEM-768** | 128-bit quantum security category; 1088-byte ciphertext; 32-byte shared secret |
| **Digital Signatures (DSA)** | NIST FIPS 204 | **ML-DSA-65** | Category 3 post-quantum signature; 3309-byte signature; 1952-byte public key |
| **Document Encryption** | NIST SP 800-38D | **AES-256-GCM** | 256-bit random content key; 96-bit random IV; 128-bit authentication tag |
| **Hashing & Merkle Trees** | NIST FIPS 202 | **SHA3-256** | 256-bit collision-resistant sponge construction with domain-separated leaves |
| **Canonical Serialization** | RFC 8785 | **Deterministic JSON** | Lexicographical key sorting; no extraneous whitespace; UTF-8 encoded |

---

## 5. Measured Watermark Robustness Benchmark

Tested on a realistic 1024×1024 classified document using block-DCT mid-frequency differential modulation on the luminance ($Y$) channel with Barker preamble synchronization and Rate-3 error correction:

| Attack / Transformation | Measured BER | Visual Quality (PSNR) | Decoded | CRC-16 Check | Extraction Time |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline (No Attack)** | **0.0%** | 361.20 dB | **YES** | **VALID** | 43.9 ms |
| **JPEG Quality 90** | **0.0%** | 37.84 dB | **YES** | **VALID** | 45.3 ms |
| **JPEG Quality 80** | **0.0%** | 35.57 dB | **YES** | **VALID** | 59.3 ms |
| **JPEG Quality 70** | **0.0%** | 33.78 dB | **YES** | **VALID** | 35.1 ms |
| **JPEG Quality 50** | **0.0%** | 31.63 dB | **YES** | **VALID** | 39.1 ms |
| **Resize 75%** | **0.0%** | 24.82 dB | **YES** | **VALID** | 37.9 ms |
| **Resize 50%** | **0.0%** | 22.11 dB | **YES** | **VALID** | 42.3 ms |
| **Crop 5%** | **0.0%** | N/A (Crop) | **YES** | **VALID** | 757.7 ms |
| **Crop 10%** | **0.0%** | N/A (Crop) | **YES** | **VALID** | 78.4 ms |
| **Gaussian Blur (3x3)** | **0.0%** | 24.06 dB | **YES** | **VALID** | 38.0 ms |
| **Gaussian Noise ($\sigma=4$)** | **0.0%** | 36.30 dB | **YES** | **VALID** | 33.3 ms |
| **Screenshot / LCD Capture** | **0.0%** | 33.31 dB | **YES** | **VALID** | 34.1 ms |
| **Print-Cam Simulation** | 57.8% | 13.52 dB | NO | FAIL | 3770.1 ms |

> [!NOTE]
> All benchmark results above are quantitatively measured by `benchmarks/run_watermark_benchmark.py`. No numbers are fabricated or artificially inflated.

---

## 6. Key Architecture Features

### 6.1 Single Document Encryption, Multi-Recipient Distribution
- The document ciphertext is created **only once** using AES-256-GCM.
- Each authorized recipient receives an independent ML-KEM-768 key capsule containing the wrapped AES content key.
- Demo supports `REC-001`, `REC-002`, and `REC-047`.

### 6.2 Commit-Before-Release Invariant
- A decrypted document is **never released** until its signed provenance record is committed to the offline ledger by $\ge 4$ of the 5 permissioned validators.
- If validator consensus fails or an invalid signature is presented, the release halts and plaintext is wiped from memory.

### 6.3 Privacy-Preserving Watermark IDs
- The embedded watermark contains only a 64-bit random **Watermark ID** and error-correcting codes.
- The recipient's true identity is **never directly embedded in the watermark**, preventing passive identity harvesting. Only parties with authorized ledger query access can link the watermark to the recipient.

### 6.4 One-Command Forensic Attribution
Run:
```bash
python -m src.cli.main trace demo/leaks/leaked_document.png
```
Output:
```
================================================================================
  EXECUTING FORENSIC TRACE ON: demo/leaks/leaked_document.png
================================================================================
WATERMARK FOUND:       YES
WATERMARK ID:          0x3F49959F3CEF651D
DOCUMENT MATCH:        YES
RECIPIENT:             REC-047
SESSION:               SESS-425AF9D587238FFEEC9749DFB5222B50
ML-DSA SIGNATURE:      VALID
MERKLE PROOF:          VALID
VALIDATOR QUORUM:      5/5 (VALID)
ATTRIBUTION:           VERIFIED
================================================================================
```

---

## 7. CLI Command Reference

| Command | Description |
| :--- | :--- |
| `setup-demo` | Initialize demo PQC identities and sample classified document |
| `encrypt` | Encrypt document into `.pqcpack` multi-recipient distribution package |
| `distribute` | Inspect distribution package manifest and recipient capsules |
| `decrypt` | Authenticate recipient, commit to ledger, embed watermark, and release document |
| `ledger-status` | Display blockchain height, tip hash, blocks, and transaction history |
| `extract-watermark` | Extract raw watermark ID and check CRC-16 from an image |
| `trace <file>` | Full forensic attribution pipeline: extraction, ledger lookup, and cryptographic proof verification |
| `verify-evidence` | Verify an exported JSON evidence bundle independently |
| `run-benchmark` | Execute the full watermark robustness benchmark attack suite |
| `run-tests` | Run the full 43-test automated unit and security test suite |

---

## 8. Security Philosophy, Limitations & Roadmap

### Honest Security Boundary
This prototype does not claim to prevent an attacker from reverse-engineering the client binary or dumping raw memory on a compromised endpoint.

### Production Solution: Variant-Segment Encryption (VSE)
To eliminate client-bypass without requiring specialized hardware (TPM/TEE), we designed **Variant-Segment Encryption**:
- Documents are split into spatial tiles.
- Visually equivalent dual variants ($T_0$ and $T_1$) are separately encrypted under independent keys ($K_0$ and $K_1$).
- The key distribution server releases **only the subset of keys matching the committed watermark sequence**.
- The recipient never possesses both keys for any tile, mathematically guaranteeing that the only document they can decrypt is already watermarked.
- Full specification: [docs/variant_segment_encryption.md](file:///c:/Users/akshi/OneDrive/Documents/Desktop/SIH-26237/docs/variant_segment_encryption.md).

For full details on attacker models and assumptions, see [THREAT_MODEL.md](file:///c:/Users/akshi/OneDrive/Documents/Desktop/SIH-26237/THREAT_MODEL.md).

---

## 9. Directory Structure

```text
SIH-26237/
├── .gitignore                      # Secrets and temporary artifact exclusions
├── README.md                       # Master system documentation
├── requirements.txt                # Pinned offline dependencies (including Flask)
├── THREAT_MODEL.md                 # Formal threat model and security specifications
├── docs/
│   ├── architecture.md             # Detailed architecture and Mermaid protocols
│   ├── offline_setup.md            # Air-gapped installation guide
│   └── variant_segment_encryption.md # Client-bypass mitigation roadmap
├── config/
│   ├── ledger_config.json          # Consortium validator configuration
│   └── recipients.json             # Example registered recipient metadata
├── frontend/
│   ├── app.py                      # Local Flask server
│   ├── templates/index.html        # Single-page cybersecurity console
│   └── static/                     # CSS styling & vanilla JS controller
├── src/
│   ├── crypto/                     # ML-KEM-768, ML-DSA-65, AES-GCM, SHA3, Canonicalization
│   ├── identity/                   # Keystore and ML-DSA Challenge-Response Auth
│   ├── watermark/                  # Transform-domain DCT, Barker Sync, ECC, Metrics
│   ├── distribution/               # Multi-recipient .pqcpack packaging
│   ├── ledger/                     # 5-Validator Permissioned DLT, 4/5 Quorum, Merkle Proofs
│   ├── decryption/                 # Decryption Session & Commit-Before-Release Enforcement
│   ├── forensics/                  # Perceptual Identity & Forensic Trace Pipeline
│   ├── evidence/                   # JSON Evidence Bundles and Human-Readable Reports
│   └── cli/                        # Unified CLI
├── benchmarks/
│   └── run_watermark_benchmark.py  # Watermark robustness evaluation harness
├── demo/
│   ├── run_demo.py                 # Turnkey end-to-end interactive demo script
│   └── simulate_leak.py            # Real-world leak attack simulator
└── tests/
    ├── test_crypto.py              # PQC and symmetric crypto tests
    ├── test_watermark.py           # Watermark and ECC tests
    ├── test_ledger.py              # Ledger, Merkle proof, and quorum tests
    ├── test_commit_before_release.py # Invariant enforcement tests
    └── test_forensics.py           # Attribution and evidence bundle tests
```
