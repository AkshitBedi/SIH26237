"""
Flask Backend Application for SIH Problem Statement 26237.
Cryptographic Attribution & Immutable Decryption Provenance Console.
Directly interfaces with the existing tested backend cryptographic modules.
"""

import os
import sys
import json
import secrets
import cv2
import numpy as np
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory

# Ensure project root is on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

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
from benchmarks.run_watermark_benchmark import create_realistic_document
from demo.simulate_leak import (
    simulate_screenshot,
    simulate_jpeg,
    simulate_crop,
    simulate_blur,
    simulate_noise,
)

app = Flask(__name__, template_folder="templates", static_folder="static")

# Default persistent directories for demo
KEYSTORE_DIR = os.path.join(ROOT_DIR, "demo", "keystores")
LEDGER_DIR = os.path.join(ROOT_DIR, "demo", "ledger_data")
PACKAGES_DIR = os.path.join(ROOT_DIR, "demo", "packages")
DECRYPTED_DIR = os.path.join(ROOT_DIR, "demo", "decrypted")
LEAKS_DIR = os.path.join(ROOT_DIR, "demo", "leaks")
EVIDENCE_DIR = os.path.join(ROOT_DIR, "demo", "evidence")
DOCS_DIR = os.path.join(ROOT_DIR, "demo", "sample_documents")

for d in [KEYSTORE_DIR, LEDGER_DIR, PACKAGES_DIR, DECRYPTED_DIR, LEAKS_DIR, EVIDENCE_DIR, DOCS_DIR]:
    os.makedirs(d, exist_ok=True)


def get_backend():
    """Instantiate existing backend keystore and permissioned ledger."""
    keystore = LocalKeystore(KEYSTORE_DIR)
    # Ensure demo identities exist
    registry = keystore.get_public_registry()
    if not registry.get("recipients"):
        keystore.setup_demo_identities()
    ledger = PermissionedLedger(keystore, LEDGER_DIR)
    return keystore, ledger


def ensure_sample_document():
    """Ensure the sample classified brief image exists."""
    doc_path = os.path.join(DOCS_DIR, "confidential_brief.png")
    if not os.path.exists(doc_path):
        img = create_realistic_document(1024, 1024)
        cv2.imwrite(doc_path, img)
    return doc_path


@app.route("/")
def index():
    ensure_sample_document()
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    keystore, ledger = get_backend()
    reg = keystore.get_public_registry()

    sample_doc = os.path.join(DOCS_DIR, "confidential_brief.png")
    has_sample = os.path.exists(sample_doc)

    latest_pkg = os.path.join(PACKAGES_DIR, "confidential_brief.pqcpack")
    has_package = os.path.exists(latest_pkg)

    latest_decrypted = os.path.join(DECRYPTED_DIR, "REC-047_document.png")
    has_decrypted = os.path.exists(latest_decrypted)

    latest_leak = os.path.join(LEAKS_DIR, "leaked_document.png")
    has_leak = os.path.exists(latest_leak)

    return jsonify({
        "status": "ONLINE",
        "air_gapped": True,
        "ledger_height": ledger.height,
        "tip_hash": ledger.tip_hash,
        "recipients": list(reg.get("recipients", {}).keys()),
        "validators": list(reg.get("validators", {}).keys()),
        "has_sample_document": has_sample,
        "has_package": has_package,
        "has_decrypted": has_decrypted,
        "has_leak": has_leak
    })


@app.route("/api/setup", methods=["POST"])
def api_setup():
    try:
        keystore, ledger = get_backend()
        keystore.setup_demo_identities()
        doc_path = ensure_sample_document()
        return jsonify({
            "success": True,
            "message": "Demo environment and PQC identities initialized.",
            "sample_document": os.path.basename(doc_path),
            "recipients": ["REC-001", "REC-002", "REC-047"],
            "validators": [f"VAL-0{i}" for i in range(1, 6)]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypts document ONCE using AES-256-GCM and wraps key via ML-KEM-768 per recipient."""
    try:
        data = request.get_json() or {}
        recipients = data.get("recipients", ["REC-001", "REC-002", "REC-047"])
        sender_id = data.get("sender_id", "SENDER-HQ")

        keystore, _ = get_backend()
        doc_path = ensure_sample_document()

        with open(doc_path, "rb") as f:
            doc_bytes = f.read()

        pkg = create_distribution_package(
            document_bytes=doc_bytes,
            recipient_ids=recipients,
            keystore=keystore,
            sender_id=sender_id,
            filename=os.path.basename(doc_path)
        )

        out_path = os.path.join(PACKAGES_DIR, "confidential_brief.pqcpack")
        save_package(pkg, out_path)

        return jsonify({
            "success": True,
            "document_hash": pkg["manifest"]["document_hash"],
            "document_size": pkg["manifest"]["document_size"],
            "recipients": recipients,
            "package_path": "demo/packages/confidential_brief.pqcpack",
            "manifest": pkg["manifest"],
            "ciphers": {
                "symmetric": "AES-256-GCM",
                "kem": "NIST FIPS 203 ML-KEM-768",
                "dsa": "NIST FIPS 204 ML-DSA-65",
                "hashing": "NIST FIPS 202 SHA3-256"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Executes atomic Commit-Before-Release decryption session."""
    try:
        data = request.get_json() or {}
        recipient_id = data.get("recipient_id", "REC-047")
        faulty_validators = data.get("faulty_validators", [])

        keystore, ledger = get_backend()
        pkg_path = os.path.join(PACKAGES_DIR, "confidential_brief.pqcpack")

        if not os.path.exists(pkg_path):
            # Auto-encrypt if not already done
            api_encrypt()

        pkg = load_package(pkg_path)
        session_mgr = DecryptionSession(keystore, ledger)

        # Execute decryption & commit-before-release
        wm_doc, record, receipt = session_mgr.decrypt_and_watermark(
            pkg,
            recipient_id,
            simulated_faulty_validators=faulty_validators
        )

        # Save decrypted watermarked document
        out_doc_path = os.path.join(DECRYPTED_DIR, f"{recipient_id}_document.png")
        cv2.imwrite(out_doc_path, wm_doc)

        # Automatically prepare default leak (screenshot attack)
        leak_img = simulate_screenshot(wm_doc)
        leak_path = os.path.join(LEAKS_DIR, "leaked_document.png")
        cv2.imwrite(leak_path, leak_img)

        return jsonify({
            "success": True,
            "recipient_id": recipient_id,
            "session_id": record["session_id"],
            "watermark_id": f"0x{record['watermark_id'].upper()}",
            "raw_watermark_id": record["watermark_id"],
            "block_height": receipt["block_height"],
            "block_hash": receipt["block_hash"],
            "previous_hash": receipt["previous_hash"],
            "quorum_count": receipt["quorum_count"],
            "validator_signatures": list(receipt["validator_signatures"].keys()),
            "signature_valid": True,
            "ledger_commit": "COMMITTED",
            "release_status": "AUTHORIZED",
            "image_url": f"/api/image/decrypted?t={int(secrets.randbelow(1000000))}",
            "leak_url": f"/api/image/leaked?t={int(secrets.randbelow(1000000))}"
        })
    except CommitBeforeReleaseError as e:
        return jsonify({
            "success": False,
            "error_type": "COMMIT_BEFORE_RELEASE_VIOLATION",
            "error": str(e)
        }), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/simulate-leak", methods=["POST"])
def api_simulate_leak():
    """Apply an isolated real-world leak transformation to the watermarked document."""
    try:
        data = request.get_json() or {}
        attack = data.get("attack", "screenshot")
        recipient_id = data.get("recipient_id", "REC-047")

        dec_path = os.path.join(DECRYPTED_DIR, f"{recipient_id}_document.png")
        if not os.path.exists(dec_path):
            dec_path = os.path.join(DECRYPTED_DIR, "REC-047_document.png")
        if not os.path.exists(dec_path):
            return jsonify({"success": False, "error": "No decrypted document found to leak. Run decryption first."}), 400

        img = cv2.imread(dec_path)
        if attack == "screenshot":
            leaked = simulate_screenshot(img)
        elif attack == "jpeg70":
            leaked = simulate_jpeg(img, 70)
        elif attack == "crop5":
            leaked = simulate_crop(img, 5)
        elif attack == "blur":
            leaked = simulate_blur(img)
        elif attack == "noise":
            leaked = simulate_noise(img)
        else:
            leaked = simulate_screenshot(img)

        leak_path = os.path.join(LEAKS_DIR, "leaked_document.png")
        cv2.imwrite(leak_path, leaked)

        return jsonify({
            "success": True,
            "attack": attack,
            "leak_path": "demo/leaks/leaked_document.png",
            "dimensions": f"{leaked.shape[1]}x{leaked.shape[0]}",
            "leak_url": f"/api/image/leaked?t={int(secrets.randbelow(1000000))}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/trace", methods=["POST"])
def api_trace():
    """One-Command Forensic Attribution Pipeline."""
    try:
        keystore, ledger = get_backend()
        ref_doc = ensure_sample_document()

        # Handle custom uploaded file if provided, otherwise default to leaked_document.png
        if 'file' in request.files and request.files['file'].filename != '':
            uploaded = request.files['file']
            leak_path = os.path.join(LEAKS_DIR, "custom_leak.png")
            uploaded.save(leak_path)
        else:
            leak_path = os.path.join(LEAKS_DIR, "leaked_document.png")

        if not os.path.exists(leak_path):
            return jsonify({"success": False, "error": "No leaked file found to trace."}), 400

        verified, bundle, report_text = trace_document(
            leak_path,
            ledger,
            keystore,
            reference_image_path=ref_doc
        )

        # Save evidence bundle
        json_path, txt_path = save_evidence(bundle, output_dir=EVIDENCE_DIR)
        json_filename = os.path.basename(json_path)

        a = bundle["attribution_evidence"]
        v = bundle["verification_results"]
        p = bundle["document_provenance"]
        c = bundle["cryptographic_signatures"]
        l = bundle["ledger_inclusion"]

        return jsonify({
            "success": True,
            "attribution_status": bundle["attribution_status"],
            "verified": verified,
            "recipient": a.get("recipient_id", "UNKNOWN"),
            "session_id": a.get("session_id", "UNKNOWN"),
            "watermark_id": f"0x{a.get('watermark_id', '').upper()}",
            "bit_error_rate": f"{a.get('bit_error_rate', 0.0) * 100.0:.2f}%",
            "document_match": "VERIFIED" if p.get("perceptual_similarity_match") else "NOT VERIFIED",
            "match_type": p.get("match_type"),
            "signature_valid": "VALID" if v.get("signature_valid") else "INVALID",
            "merkle_proof_valid": "VALID" if v.get("merkle_proof_valid") else "INVALID",
            "validator_quorum": f"{c.get('validator_quorum_count', '5/5')} (VALID)" if v.get("validator_quorum_valid") else "FAILED",
            "block_height": l.get("block_height"),
            "block_hash": l.get("block_hash"),
            "evidence_json_filename": json_filename,
            "evidence_json_url": f"/api/evidence/download/{json_filename}",
            "evidence_report": report_text,
            "evidence_bundle": bundle
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/run-full-demo", methods=["POST"])
def api_run_full_demo():
    """One-click turnkey demo execution for evaluators."""
    try:
        # Step 1: Setup
        keystore, ledger = get_backend()
        keystore.setup_demo_identities()
        doc_path = ensure_sample_document()

        # Step 2: Encrypt
        with open(doc_path, "rb") as f:
            doc_bytes = f.read()
        pkg = create_distribution_package(
            doc_bytes,
            ["REC-001", "REC-002", "REC-047"],
            keystore,
            sender_id="SENDER-HQ",
            filename="confidential_brief.png"
        )
        pkg_path = os.path.join(PACKAGES_DIR, "confidential_brief.pqcpack")
        save_package(pkg, pkg_path)

        # Step 3: Decrypt as REC-047
        session_mgr = DecryptionSession(keystore, ledger)
        wm_doc, record, receipt = session_mgr.decrypt_and_watermark(pkg, "REC-047")
        dec_path = os.path.join(DECRYPTED_DIR, "REC-047_document.png")
        cv2.imwrite(dec_path, wm_doc)

        # Step 4: Simulate Leak
        leaked = simulate_screenshot(wm_doc)
        leak_path = os.path.join(LEAKS_DIR, "leaked_document.png")
        cv2.imwrite(leak_path, leaked)

        # Step 5: Trace
        verified, bundle, report = trace_document(leak_path, ledger, keystore, reference_image_path=doc_path)
        json_path, _ = save_evidence(bundle, output_dir=EVIDENCE_DIR)

        return jsonify({
            "success": True,
            "step_encrypt": {
                "doc_hash": pkg["manifest"]["document_hash"],
                "recipients": ["REC-001", "REC-002", "REC-047"]
            },
            "step_decrypt": {
                "recipient": "REC-047",
                "session_id": record["session_id"],
                "watermark_id": f"0x{record['watermark_id'].upper()}",
                "block_height": receipt["block_height"],
                "quorum": receipt["quorum_count"]
            },
            "step_trace": {
                "attribution_status": bundle["attribution_status"],
                "recipient": bundle["attribution_evidence"]["recipient_id"],
                "session_id": bundle["attribution_evidence"]["session_id"],
                "watermark_id": f"0x{bundle['attribution_evidence']['watermark_id'].upper()}",
                "evidence_url": f"/api/evidence/download/{os.path.basename(json_path)}"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/evidence/download/<filename>")
def download_evidence(filename):
    return send_from_directory(EVIDENCE_DIR, filename, as_attachment=True)


@app.route("/api/image/<img_type>")
def get_image(img_type):
    if img_type == "sample":
        path = os.path.join(DOCS_DIR, "confidential_brief.png")
    elif img_type == "decrypted":
        path = os.path.join(DECRYPTED_DIR, "REC-047_document.png")
    elif img_type == "leaked":
        path = os.path.join(LEAKS_DIR, "leaked_document.png")
    else:
        return "Not found", 404

    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    return "Not found", 404


if __name__ == "__main__":
    ensure_sample_document()
    print("=" * 80)
    print("  SIH 26237: CRYPTOGRAPHIC ATTRIBUTION & PROVENANCE CONSOLE")
    print("  Running locally at: http://127.0.0.1:5000")
    print("=" * 80)
    app.run(host="127.0.0.1", port=5000, debug=False)
