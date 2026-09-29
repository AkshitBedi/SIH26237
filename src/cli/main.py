"""
Unified Command-Line Interface (CLI) for SIH Problem Statement 26237.
Cryptographic Attribution and Immutable Decryption Provenance Prototype.
"""

import os
import sys
import argparse
import json
import cv2
import numpy as np

# Ensure root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.identity.keystore import LocalKeystore
from src.ledger.ledger import PermissionedLedger
from src.distribution.package import (
    create_distribution_package,
    save_package,
    load_package,
)
from src.decryption.session import DecryptionSession, CommitBeforeReleaseError
from src.forensics.trace import trace_document
from src.evidence.bundle import save_evidence, format_evidence_report
from src.watermark.transform import extract_watermark
from benchmarks.run_watermark_benchmark import create_realistic_document, run_benchmark


DEFAULT_KEYSTORE_DIR = "demo/keystores"
DEFAULT_LEDGER_DIR = "demo/ledger_data"


def get_keystore_and_ledger(keystore_dir=DEFAULT_KEYSTORE_DIR, ledger_dir=DEFAULT_LEDGER_DIR):
    keystore = LocalKeystore(keystore_dir)
    ledger = PermissionedLedger(keystore, ledger_dir)
    return keystore, ledger


def cmd_setup_demo(args):
    print("=" * 80)
    print("  [SIH-26237] INITIALIZING DEMO ENVIRONMENT & PQC IDENTITIES")
    print("=" * 80)
    keystore, ledger = get_keystore_and_ledger(args.keystore, args.ledger)

    print("[*] Generating Post-Quantum Identities (ML-KEM-768 + ML-DSA-65)...")
    registry = keystore.setup_demo_identities()

    print(f"  [+] Registered {len(registry['recipients'])} Recipients: {', '.join(registry['recipients'].keys())}")
    print(f"  [+] Registered {len(registry['validators'])} Permissioned Validators: {', '.join(registry['validators'].keys())}")
    print(f"  [+] Registered 1 Dispatch Authority: {', '.join(registry['senders'].keys())}")

    # Generate sample document
    demo_doc_dir = "demo/sample_documents"
    os.makedirs(demo_doc_dir, exist_ok=True)
    doc_path = os.path.join(demo_doc_dir, "confidential_brief.png")
    if not os.path.exists(doc_path):
        doc_img = create_realistic_document(1024, 1024)
        cv2.imwrite(doc_path, doc_img)
        print(f"  [+] Generated Sample Classified Document: {doc_path}")
    else:
        print(f"  [+] Sample Document Exists: {doc_path}")

    print("[+] Demo environment setup complete.")


def cmd_encrypt(args):
    keystore, _ = get_keystore_and_ledger(args.keystore, args.ledger)
    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}")
        sys.exit(1)

    with open(args.input, "rb") as f:
        doc_bytes = f.read()

    recipients = [r.strip() for r in args.recipients.split(",") if r.strip()]
    print(f"[*] Packaging document ({len(doc_bytes)} bytes) for {len(recipients)} recipients: {recipients}")
    print("    - Document Encrypted ONCE using AES-256-GCM")
    print("    - Content Key Encapsulated per recipient via NIST FIPS 203 ML-KEM-768")
    print("    - Package Signed with Sender ML-DSA-65 Private Key")

    pkg = create_distribution_package(
        doc_bytes,
        recipients,
        keystore,
        sender_id=args.sender,
        filename=os.path.basename(args.input)
    )

    out_path = args.output or f"demo/packages/{os.path.splitext(os.path.basename(args.input))[0]}.pqcpack"
    save_package(pkg, out_path)
    print(f"[+] Multi-recipient package successfully saved to: {out_path}")
    print(f"    Document SHA3-256: {pkg['manifest']['document_hash']}")


def cmd_distribute(args):
    if not os.path.exists(args.package):
        print(f"[-] Package not found: {args.package}")
        sys.exit(1)

    pkg = load_package(args.package)
    m = pkg["manifest"]
    print("=" * 80)
    print("  POST-QUANTUM DISTRIBUTION PACKAGE MANIFEST")
    print("=" * 80)
    print(f"Format:              {m.get('format')}")
    print(f"Sender ID:           {m.get('sender_id')}")
    print(f"Filename:            {m.get('filename')}")
    print(f"Document Size:       {m.get('document_size')} bytes")
    print(f"Document SHA3-256:   {m.get('document_hash')}")
    print(f"Authorized Count:    {m.get('recipient_count')}")
    print(f"Recipients:          {', '.join(m.get('recipients', []))}")
    print("-" * 80)
    print("RECIPIENT KEY CAPSULES:")
    for r_id, cap in pkg.get("recipient_capsules", {}).items():
        print(f"  - {r_id:<10} | KEM Capsule: {len(cap['kem_ciphertext'])} b64 chars | Wrapped Key: {len(cap['wrapped_key'])} b64 chars")
    print("=" * 80)


def cmd_decrypt(args):
    keystore, ledger = get_keystore_and_ledger(args.keystore, args.ledger)
    if not os.path.exists(args.package):
        print(f"[-] Package not found: {args.package}")
        sys.exit(1)

    pkg = load_package(args.package)
    session_mgr = DecryptionSession(keystore, ledger)

    faulty = [v.strip() for v in args.faulty_validators.split(",") if v.strip()] if args.faulty_validators else None

    print("=" * 80)
    print(f"  INITIATING DECRYPTION SESSION FOR RECIPIENT: {args.recipient}")
    print("=" * 80)
    print("  [1/5] Recipient Challenge-Response Authentication (ML-DSA-65)...")
    print("  [2/5] Key Decapsulation (ML-KEM-768) & Document Decryption (AES-256-GCM)...")
    print("  [3/5] Constructing Canonical Provenance Record & Signing with Recipient Key...")
    print("  [4/5] Enforcing 4-of-5 Ledger Commitment Quorum (Commit-Before-Release)...")

    try:
        wm_doc, record, receipt = session_mgr.decrypt_and_watermark(
            pkg,
            args.recipient,
            simulated_faulty_validators=faulty
        )
        print("  [5/5] Ledger Commitment Confirmed. Embedding Session Watermark & Releasing.")
        print("-" * 80)
        print(f"[+] DECRYPTION SUCCESSFUL (Commit-Before-Release Satisfied)")
        print(f"    Block Committed:     #{receipt['block_height']}")
        print(f"    Block Hash:          {receipt['block_hash']}")
        print(f"    Validator Quorum:    {receipt['quorum_count']}")
        print(f"    Assigned Session ID: {record['session_id']}")
        print(f"    Watermark ID:        0x{record['watermark_id'].upper()}")

        out_path = args.output or f"demo/decrypted/{args.recipient}_document.png"
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        cv2.imwrite(out_path, wm_doc)
        print(f"[+] Released Watermarked Document Saved to: {out_path}")

    except CommitBeforeReleaseError as e:
        print(f"[-] CRITICAL SECURITY INVARIANT HALT: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Decryption error: {str(e)}")
        sys.exit(1)


def cmd_ledger_status(args):
    keystore, ledger = get_keystore_and_ledger(args.keystore, args.ledger)
    primary = ledger.validators[ledger.validator_ids[0]]
    chain = primary.chain

    print("=" * 80)
    print(f"  OFFLINE PERMISSIONED LEDGER STATUS (Height: {ledger.height})")
    print("=" * 80)
    print(f"Tip Block Hash: {ledger.tip_hash}")
    print(f"Active Validators: {', '.join(ledger.validator_ids)}")
    print("-" * 80)
    for b in chain:
        h = b.header
        print(f"Block #{h['height']:<3} | Hash: {b.block_hash[:16]}... | Prev: {h['previous_hash'][:16]}... | Txs: {h['tx_count']} | Quorum: {len(b.validator_signatures)}/5")
        for idx, tx in enumerate(b.transactions):
            if tx.get("type") == "GENESIS":
                print(f"   └── Tx {idx}: [GENESIS] {tx.get('description')}")
            else:
                print(f"   └── Tx {idx}: [DECRYPT] Recipient: {tx.get('recipient_id')} | Session: {tx.get('session_id')} | Watermark: 0x{tx.get('watermark_id', '').upper()}")
    print("=" * 80)
    valid, msg = ledger.verify_chain_integrity()
    print(f"Chain Cryptographic Integrity: {'VALID' if valid else 'INVALID'} ({msg})")


def cmd_extract_watermark(args):
    if not os.path.exists(args.image):
        print(f"[-] Image not found: {args.image}")
        sys.exit(1)

    img = cv2.imread(args.image)
    wm_id, ber, crc_valid, meta = extract_watermark(img, search_shifts=True)
    print("=" * 80)
    print("  WATERMARK EXTRACTION RESULT")
    print("=" * 80)
    if crc_valid and wm_id:
        print(f"Watermark Found:       YES")
        print(f"Watermark ID:          0x{wm_id.upper()}")
        print(f"CRC-16 Status:         VALID")
        print(f"Estimated BER:         {ber * 100.0:.2f}%")
        print(f"Barker Correlation:    {meta.get('barker_correlation', 0.0):.2f}")
        print(f"Alignment Shift:       Pixel {meta.get('pixel_shift')} | Block {meta.get('block_offset')}")
    else:
        print(f"Watermark Found:       NO (Extraction or CRC failure)")
        print(f"Estimated BER:         {ber * 100.0:.2f}%")


def cmd_trace(args):
    keystore, ledger = get_keystore_and_ledger(args.keystore, args.ledger)
    ref_path = args.reference or "demo/sample_documents/confidential_brief.png"

    print("=" * 80)
    print(f"  EXECUTING FORENSIC TRACE ON: {args.image}")
    print("=" * 80)

    try:
        verified, bundle, report_text = trace_document(
            args.image,
            ledger,
            keystore,
            reference_image_path=ref_path if os.path.exists(ref_path) else None
        )

        # Print Judge-format summary
        a = bundle["attribution_evidence"]
        v = bundle["verification_results"]
        p = bundle["document_provenance"]
        c = bundle["cryptographic_signatures"]

        print(f"WATERMARK FOUND:       {'YES' if v['watermark_found'] else 'NO'}")
        if v['watermark_found']:
            print(f"WATERMARK ID:          0x{a['watermark_id'].upper()}")
            print(f"DOCUMENT MATCH:        {'YES' if p['perceptual_similarity_match'] else 'NO'}")
            print(f"RECIPIENT:             {a['recipient_id']}")
            print(f"SESSION:               {a['session_id']}")
            print(f"ML-DSA SIGNATURE:      {'VALID' if v['signature_valid'] else 'INVALID'}")
            print(f"MERKLE PROOF:          {'VALID' if v['merkle_proof_valid'] else 'INVALID'}")
            print(f"VALIDATOR QUORUM:      {c['validator_quorum_count']} ({'VALID' if v['validator_quorum_valid'] else 'FAILED'})")
            print(f"ATTRIBUTION:           {bundle['attribution_status']}")
        else:
            print(f"ATTRIBUTION:           FAILED (No watermark recovered)")

        print("=" * 80)

        # Save evidence bundle
        out_dir = args.evidence_dir or "demo/evidence"
        j_path, t_path = save_evidence(bundle, output_dir=out_dir)
        print(f"[+] Evidence Bundle Saved:  {j_path}")
        print(f"[+] Forensic Report Saved:  {t_path}")

    except Exception as e:
        print(f"[-] Trace error: {str(e)}")
        sys.exit(1)


def cmd_verify_evidence(args):
    if not os.path.exists(args.evidence):
        print(f"[-] Evidence file not found: {args.evidence}")
        sys.exit(1)

    with open(args.evidence, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    print("=" * 80)
    print("  VERIFYING STORED EVIDENCE BUNDLE")
    print("=" * 80)
    print(format_evidence_report(bundle))


def cmd_benchmark(args):
    run_benchmark(output_dir="benchmarks")


def cmd_tests(args):
    import unittest
    suite = unittest.defaultTestLoader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(
        description="SIH-26237: Cryptographic Attribution and Immutable Provenance Prototype"
    )
    parser.add_argument("--keystore", default=DEFAULT_KEYSTORE_DIR, help="Keystore directory")
    parser.add_argument("--ledger", default=DEFAULT_LEDGER_DIR, help="Ledger data directory")

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # setup-demo
    p_setup = subparsers.add_parser("setup-demo", help="Initialize demo identities and sample document")
    p_setup.set_defaults(func=cmd_setup_demo)

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt document for multiple recipients")
    p_enc.add_argument("--input", "-i", required=True, help="Input document path")
    p_enc.add_argument("--recipients", "-r", required=True, help="Comma-separated recipient IDs")
    p_enc.add_argument("--sender", "-s", default="SENDER-HQ", help="Sender ID")
    p_enc.add_argument("--output", "-o", help="Output package path (.pqcpack)")
    p_enc.set_defaults(func=cmd_encrypt)

    # distribute
    p_dist = subparsers.add_parser("distribute", help="Display package distribution metadata")
    p_dist.add_argument("--package", "-p", required=True, help="Path to .pqcpack file")
    p_dist.set_defaults(func=cmd_distribute)

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Authenticate and decrypt document with commit-before-release")
    p_dec.add_argument("--package", "-p", required=True, help="Path to .pqcpack file")
    p_dec.add_argument("--recipient", "-r", required=True, help="Recipient ID")
    p_dec.add_argument("--output", "-o", help="Output watermarked image path")
    p_dec.add_argument("--faulty-validators", help="Comma-separated faulty validator IDs")
    p_dec.set_defaults(func=cmd_decrypt)

    # ledger-status
    p_ls = subparsers.add_parser("ledger-status", help="Inspect offline ledger blockchain and transactions")
    p_ls.set_defaults(func=cmd_ledger_status)

    # extract-watermark
    p_ew = subparsers.add_parser("extract-watermark", help="Extract raw watermark from an image")
    p_ew.add_argument("--image", "-i", required=True, help="Image file path")
    p_ew.set_defaults(func=cmd_extract_watermark)

    # trace
    p_trace = subparsers.add_parser("trace", help="One-command forensic attribution of leaked document")
    p_trace.add_argument("image", help="Leaked image file path")
    p_trace.add_argument("--reference", help="Optional reference document path for visual similarity")
    p_trace.add_argument("--evidence-dir", help="Directory to save evidence bundle")
    p_trace.set_defaults(func=cmd_trace)

    # verify-evidence
    p_ve = subparsers.add_parser("verify-evidence", help="Verify saved JSON evidence bundle")
    p_ve.add_argument("--evidence", "-e", required=True, help="Evidence bundle JSON path")
    p_ve.set_defaults(func=cmd_verify_evidence)

    # run-benchmark
    p_bm = subparsers.add_parser("run-benchmark", help="Run watermark robustness benchmark")
    p_bm.set_defaults(func=cmd_benchmark)

    # run-tests
    p_test = subparsers.add_parser("run-tests", help="Run full automated unit and security test suite")
    p_test.set_defaults(func=cmd_tests)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
