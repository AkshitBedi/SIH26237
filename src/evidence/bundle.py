"""
Forensic Evidence Bundle Generator and Human-Readable Report Formatter.
SIH Problem Statement 26237.
"""

import os
import json
import time
from typing import Dict, Any, Tuple


def create_evidence_bundle(
    attribution_status: str,
    document_match: bool,
    document_identity_details: Dict[str, Any],
    watermark_found: bool,
    watermark_id: str,
    bit_error_rate: float,
    recipient_id: str,
    session_id: str,
    decryption_timestamp: int,
    decryption_nonce: str,
    block_height: int,
    block_hash: str,
    merkle_root: str,
    merkle_proof: Dict[str, Any],
    recipient_public_key_fingerprint: str,
    recipient_mldsa_signature: str,
    validator_signatures: Dict[str, str],
    signature_valid: bool,
    merkle_proof_valid: bool,
    block_valid: bool,
    validator_quorum_valid: bool,
    verification_summary: str
) -> Dict[str, Any]:
    """Assemble structured machine-readable JSON forensic evidence bundle."""
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attribution_status": attribution_status,
        "verification_results": {
            "document_match": document_match,
            "watermark_found": watermark_found,
            "signature_valid": signature_valid,
            "merkle_proof_valid": merkle_proof_valid,
            "block_valid": block_valid,
            "validator_quorum_valid": validator_quorum_valid,
            "all_verifications_passed": (
                watermark_found and signature_valid and merkle_proof_valid and
                block_valid and validator_quorum_valid
            )
        },
        "attribution_evidence": {
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "bit_error_rate": round(bit_error_rate, 4),
            "decryption_timestamp": decryption_timestamp,
            "nonce": decryption_nonce
        },
        "document_provenance": {
            "expected_document_hash": document_identity_details.get("reference_sha3_256"),
            "candidate_sha3_256": document_identity_details.get("candidate_sha3_256"),
            "match_type": document_identity_details.get("match_type"),
            "exact_cryptographic_match": document_identity_details.get("exact_cryptographic_match", False),
            "perceptual_similarity_match": document_identity_details.get("perceptual_similarity_match", False),
            "perceptual_confidence": document_identity_details.get("perceptual_confidence", 0.0)
        },
        "cryptographic_signatures": {
            "recipient_id": recipient_id,
            "recipient_dsa_fingerprint": recipient_public_key_fingerprint,
            "recipient_mldsa_signature": recipient_mldsa_signature,
            "validator_signatures": validator_signatures,
            "validator_quorum_count": f"{len(validator_signatures)}/5"
        },
        "ledger_inclusion": {
            "block_height": block_height,
            "block_hash": block_hash,
            "merkle_root": merkle_root,
            "merkle_proof": merkle_proof
        },
        "summary": verification_summary
    }


def format_evidence_report(bundle: Dict[str, Any]) -> str:
    """Format evidence bundle into human-readable terminal report."""
    v = bundle["verification_results"]
    a = bundle["attribution_evidence"]
    p = bundle["document_provenance"]
    c = bundle["cryptographic_signatures"]
    l = bundle["ledger_inclusion"]

    status = bundle["attribution_status"]
    status_symbol = "[+] SUCCESS" if status == "VERIFIED" else "[-] REJECTED"

    report = []
    report.append("=" * 80)
    report.append(f"       SIH-26237 FORENSIC ATTRIBUTION REPORT: {status}")
    report.append("=" * 80)
    report.append(f"Status:                      {status_symbol} ({status})")
    report.append(f"Attributed Recipient:        {a.get('recipient_id', 'UNKNOWN')}")
    report.append(f"Decryption Session ID:       {a.get('session_id', 'UNKNOWN')}")
    report.append(f"Watermark Identifier:        0x{a.get('watermark_id', 'UNKNOWN').upper()}")
    report.append(f"Watermark Bit Error Rate:    {a.get('bit_error_rate', 0.0) * 100.0:.2f}%")
    report.append(f"Document Visual Match:       {'YES' if p.get('perceptual_similarity_match') else 'NO'} ({p.get('match_type')})")
    report.append(f"Cryptographic Hash Match:    {'YES' if p.get('exact_cryptographic_match') else 'NO (Modified/Compressed)'}")
    report.append("-" * 80)
    report.append("CRYPTOGRAPHIC PROVENANCE VERIFICATION:")
    report.append(f"  [x] Recipient ML-DSA-65 Signature:  {'VALID' if v.get('signature_valid') else 'INVALID'}")
    report.append(f"  [x] Merkle Inclusion Proof:         {'VALID' if v.get('merkle_proof_valid') else 'INVALID'}")
    report.append(f"  [x] Block Hash Chaining:            {'VALID' if v.get('block_valid') else 'INVALID'}")
    report.append(f"  [x] Validator Consensus Quorum:     {'VALID (' + c.get('validator_quorum_count', '') + ')' if v.get('validator_quorum_valid') else 'FAILED'}")
    report.append("-" * 80)
    report.append("LEDGER ANCHOR DETAILS:")
    report.append(f"  Block Height:              #{l.get('block_height')}")
    report.append(f"  Block Hash:                {l.get('block_hash')}")
    report.append(f"  Merkle Root:               {l.get('merkle_root')}")
    report.append(f"  Attested Timestamp:        {a.get('decryption_timestamp')} UTC")
    report.append("=" * 80)
    return "\n".join(report)


def save_evidence(
    bundle: Dict[str, Any],
    output_dir: str = "demo/evidence",
    prefix: str = "evidence_bundle"
) -> Tuple[str, str]:
    """Save JSON bundle and text report to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp_slug = time.strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"{prefix}_{timestamp_slug}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    txt_path = os.path.join(output_dir, f"{prefix}_{timestamp_slug}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(format_evidence_report(bundle))

    return json_path, txt_path
