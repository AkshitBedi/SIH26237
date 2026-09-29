"""
Multi-Recipient Post-Quantum Document Distribution Package Builder and Parser.
- Encrypts document ONCE using AES-256-GCM.
- Encapsulates AES content key for each recipient via NIST FIPS 203 ML-KEM-768.
- Signs distribution manifest with Sender's NIST FIPS 204 ML-DSA-65 key.
SIH Problem Statement 26237.
"""

import os
import json
import base64
import time
from typing import Dict, Any, List, Tuple
from src.crypto.symmetric import (
    sha3_256,
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from src.crypto.canonical import canonicalize
from src.crypto.pqc import (
    mlkem_encapsulate,
    mlkem_decapsulate,
    mldsa_sign,
    mldsa_verify,
)
from src.identity.keystore import LocalKeystore


def create_distribution_package(
    document_bytes: bytes,
    recipient_ids: List[str],
    keystore: LocalKeystore,
    sender_id: str = "SENDER-HQ",
    filename: str = "classified_document.png"
) -> Dict[str, Any]:
    """
    Build a multi-recipient post-quantum encrypted package.
    The document payload is encrypted once; the content key is wrapped per recipient via ML-KEM-768.
    """
    if not recipient_ids:
        raise ValueError("At least one recipient must be specified.")

    # 1. Document SHA3-256 Hash
    doc_hash = sha3_256(document_bytes)

    # 2. Generate random 256-bit AES Content Key
    content_key = generate_aes_key()

    # 3. Encrypt document once with AES-256-GCM
    doc_nonce = generate_nonce()
    ct, n, tag = encrypt_aes_gcm(
        document_bytes,
        content_key,
        nonce=doc_nonce,
        associated_data=doc_hash.encode('utf-8')
    )

    # 4. For each recipient: ML-KEM-768 encapsulation of the content key
    recipient_capsules: Dict[str, Dict[str, str]] = {}
    for r_id in recipient_ids:
        pub_kem = keystore.get_recipient_kem_public_key(r_id)
        shared_secret, kem_ct = mlkem_encapsulate(pub_kem)

        # Wrap AES content key using shared_secret
        wrap_nonce = generate_nonce()
        wrapped_key, w_nonce, w_tag = encrypt_aes_gcm(
            content_key,
            shared_secret,
            nonce=wrap_nonce,
            associated_data=r_id.encode('utf-8')
        )

        recipient_capsules[r_id] = {
            "kem_ciphertext": base64.b64encode(kem_ct).decode('utf-8'),
            "wrapped_key": base64.b64encode(wrapped_key).decode('utf-8'),
            "wrap_nonce": base64.b64encode(w_nonce).decode('utf-8'),
            "wrap_tag": base64.b64encode(w_tag).decode('utf-8')
        }

    # 5. Build package manifest
    manifest = {
        "version": "1.0",
        "format": "SIH-PQC-DISTRIBUTION-PACKAGE",
        "sender_id": sender_id,
        "filename": filename,
        "document_hash": doc_hash,
        "document_size": len(document_bytes),
        "timestamp": int(time.time()),
        "recipient_count": len(recipient_ids),
        "recipients": list(recipient_capsules.keys())
    }

    # 6. Sign manifest with Sender ML-DSA-65 key
    sender_priv = keystore.get_sender_dsa_private_key(sender_id)
    manifest_bytes = canonicalize(manifest)
    sender_sig = mldsa_sign(sender_priv, manifest_bytes)
    sender_sig_b64 = base64.b64encode(sender_sig).decode('utf-8')

    package = {
        "manifest": manifest,
        "sender_signature": sender_sig_b64,
        "recipient_capsules": recipient_capsules,
        "encrypted_payload": {
            "ciphertext": base64.b64encode(ct).decode('utf-8'),
            "nonce": base64.b64encode(n).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
    }

    return package


def save_package(package: Dict[str, Any], filepath: str) -> None:
    """Save package to disk (.pqcpack)."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2)


def load_package(filepath: str) -> Dict[str, Any]:
    """Load package from disk."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def unwrap_content_key(
    package: Dict[str, Any],
    recipient_id: str,
    keystore: LocalKeystore
) -> bytes:
    """
    Recipient decapsulates shared secret using their ML-KEM-768 private key,
    and unwraps the AES content key.
    """
    capsules = package.get("recipient_capsules", {})
    if recipient_id not in capsules:
        raise PermissionError(f"Recipient {recipient_id} is not in package recipient list.")

    cap = capsules[recipient_id]
    kem_ct = base64.b64decode(cap["kem_ciphertext"])
    wrapped_key = base64.b64decode(cap["wrapped_key"])
    wrap_nonce = base64.b64decode(cap["wrap_nonce"])
    wrap_tag = base64.b64decode(cap["wrap_tag"])

    # 1. ML-KEM decapsulation
    kem_priv = keystore.get_recipient_kem_private_key(recipient_id)
    shared_secret = mlkem_decapsulate(kem_priv, kem_ct)

    # 2. Unwrap AES content key
    content_key = decrypt_aes_gcm(
        wrapped_key,
        shared_secret,
        nonce=wrap_nonce,
        tag=wrap_tag,
        associated_data=recipient_id.encode('utf-8')
    )

    return content_key


def decrypt_document_payload(package: Dict[str, Any], content_key: bytes) -> bytes:
    """Decrypt the single encrypted document payload using unwrapped content key."""
    enc = package["encrypted_payload"]
    ct = base64.b64decode(enc["ciphertext"])
    nonce = base64.b64decode(enc["nonce"])
    tag = base64.b64decode(enc["tag"])
    doc_hash = package["manifest"]["document_hash"]

    plaintext = decrypt_aes_gcm(
        ct,
        content_key,
        nonce=nonce,
        tag=tag,
        associated_data=doc_hash.encode('utf-8')
    )

    # Verify integrity
    computed_hash = sha3_256(plaintext)
    if computed_hash != doc_hash:
        raise ValueError(f"Integrity check failed: expected {doc_hash}, got {computed_hash}")

    return plaintext
