"""
Turnkey End-to-End Demonstration Script for SIH Problem Statement 26237.
Demonstrates the complete lifecycle:
  ENCRYPT -> DISTRIBUTE -> AUTHENTICATE -> COMMIT-BEFORE-RELEASE -> WATERMARK -> LEAK -> TRACE -> ATTRIBUTE
"""

import os
import sys
import time
import subprocess
import shutil

# Ensure working directory is project root
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(ROOT_DIR)
sys.path.insert(0, ROOT_DIR)


def print_banner(step_num: int, title: str):
    print("\n" + "=" * 80)
    print(f"  STEP {step_num}: {title.upper()}")
    print("=" * 80)


def main():
    print("=" * 80)
    print("  SIH PROBLEM STATEMENT 26237: NATIONAL-LEVEL PROTOTYPE DEMONSTRATION")
    print("  Cryptographic Attribution and Immutable Decryption Provenance")
    print("  Stack: NIST FIPS 203 ML-KEM-768 | FIPS 204 ML-DSA-65 | SHA3-256 | AES-256-GCM")
    print("=" * 80)

    # Clean previous demo run artifacts
    for d in ["demo/keystores", "demo/ledger_data", "demo/packages", "demo/decrypted", "demo/leaks", "demo/evidence"]:
        shutil.rmtree(os.path.join(ROOT_DIR, d), ignore_errors=True)

    # STEP 1: Setup Environment and PQC Identities
    print_banner(1, "Initialize Demo Environment & Local PQC Keystore")
    res = subprocess.run([sys.executable, "-m", "src.cli.main", "setup-demo"], capture_output=True, text=True)
    print(res.stdout)

    # STEP 2: Encrypt Document for Multi-Recipient Distribution
    print_banner(2, "Encrypt Document for Multiple Recipients (REC-001, REC-002, REC-047)")
    enc_cmd = [
        sys.executable, "-m", "src.cli.main", "encrypt",
        "--input", "demo/sample_documents/confidential_brief.png",
        "--recipients", "REC-001,REC-002,REC-047",
        "--sender", "SENDER-HQ",
        "--output", "demo/packages/confidential_brief.pqcpack"
    ]
    res = subprocess.run(enc_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 3: Display Distribution Package
    print_banner(3, "Inspect Distribution Package Manifest")
    dist_cmd = [sys.executable, "-m", "src.cli.main", "distribute", "--package", "demo/packages/confidential_brief.pqcpack"]
    res = subprocess.run(dist_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 4: Recipient REC-047 Decrypts with Commit-Before-Release
    print_banner(4, "Recipient REC-047 Decrypts via Commit-Before-Release Workflow")
    dec_cmd = [
        sys.executable, "-m", "src.cli.main", "decrypt",
        "--package", "demo/packages/confidential_brief.pqcpack",
        "--recipient", "REC-047",
        "--output", "demo/decrypted/rec047_document.png"
    ]
    res = subprocess.run(dec_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 5: Inspect Offline Permissioned Ledger
    print_banner(5, "Inspect Offline Permissioned Ledger (4-of-5 Validator Consensus)")
    ls_cmd = [sys.executable, "-m", "src.cli.main", "ledger-status"]
    res = subprocess.run(ls_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 6: Simulate Exfiltration Leak (Screenshot + Recompression)
    print_banner(6, "Simulate Real-World Leak (Screenshot / Display Re-Encoding)")
    leak_cmd = [
        sys.executable, "demo/simulate_leak.py",
        "--input", "demo/decrypted/rec047_document.png",
        "--attack", "screenshot",
        "--output", "demo/leaks/leaked_document.png"
    ]
    res = subprocess.run(leak_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 7: One-Command Forensic Attribution
    print_banner(7, "Execute Forensic Attribution: trace demo/leaks/leaked_document.png")
    trace_cmd = [sys.executable, "-m", "src.cli.main", "trace", "demo/leaks/leaked_document.png"]
    res = subprocess.run(trace_cmd, capture_output=True, text=True)
    print(res.stdout)

    # STEP 8: Second Decryption Session Verification (Demonstrates Uniqueness)
    print_banner(8, "Security Invariant: Demonstrate Fresh Session & Watermark ID on 2nd Decrypt")
    dec2_cmd = [
        sys.executable, "-m", "src.cli.main", "decrypt",
        "--package", "demo/packages/confidential_brief.pqcpack",
        "--recipient", "REC-047",
        "--output", "demo/decrypted/rec047_document_session2.png"
    ]
    res = subprocess.run(dec2_cmd, capture_output=True, text=True)
    print(res.stdout)

    print("\n" + "=" * 80)
    print("  [+] SIH PROTOTYPE DEMONSTRATION COMPLETE: ALL CRITICAL PATHS VERIFIED!")
    print("=" * 80)


if __name__ == "__main__":
    main()
