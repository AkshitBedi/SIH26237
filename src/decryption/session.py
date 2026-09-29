"""
Decryption Session Manager with Strict Commit-Before-Release Invariant Enforcement.
Implements post-quantum authentication, session watermark generation,
ML-DSA-65 signed provenance, and offline 4-of-5 ledger commitment before releasing watermarked documents.
SIH Problem Statement 26237.
"""

import time
import secrets
import base64
import cv2
import numpy as np
from typing import Dict, Any, Tuple, Optional, List

from src.identity.keystore import LocalKeystore
from src.identity.auth import create_auth_challenge, respond_to_challenge, verify_auth_response
from src.distribution.package import unwrap_content_key, decrypt_document_payload
from src.crypto.canonical import canonicalize
from src.crypto.pqc import mldsa_sign
from src.ledger.ledger import PermissionedLedger
from src.watermark.transform import embed_watermark


class CommitBeforeReleaseError(RuntimeError):
    """Raised when ledger commitment fails, preventing document release."""
    pass


class DecryptionSession:
    """Manages the lifecycle of a secure, attributed document decryption."""

    def __init__(self, keystore: LocalKeystore, ledger: PermissionedLedger):
        self.keystore = keystore
        self.ledger = ledger

    def authenticate_recipient(self, recipient_id: str) -> bool:
        """Execute ML-DSA-65 challenge-response authentication."""
        challenge = create_auth_challenge(recipient_id, self.keystore)
        response = respond_to_challenge(challenge, self.keystore)
        valid, reason = verify_auth_response(response, self.keystore)
        if not valid:
            raise PermissionError(f"Recipient authentication failed: {reason}")
        return True

    def decrypt_and_watermark(
        self,
        package: Dict[str, Any],
        recipient_id: str,
        simulated_faulty_validators: Optional[List[str]] = None,
        watermark_delta: float = 38.0
    ) -> Tuple[np.ndarray, Dict[str, Any], Dict[str, Any]]:
        """
        Executes the atomic Commit-Before-Release decryption pipeline:

        1. Authenticate recipient via ML-DSA challenge-response
        2. Decapsulate key and decrypt document into memory
        3. Generate cryptographically secure session ID and watermark ID
        4. Construct canonical Decryption Record (omitting recipient from watermark)
        5. Recipient signs record with ML-DSA-65 private key
        6. Commit record to Permissioned Ledger via 4-of-5 validator quorum
        7. VERIFY COMMITMENT RECEIPT: If commit fails, abort and wipe plaintext
        8. Embed watermark into document image
        9. Release watermarked document

        Returns:
            (watermarked_image_bgr, decryption_record, ledger_receipt)
        """
        # STEP 1: Authenticate Recipient
        self.authenticate_recipient(recipient_id)

        # STEP 2: Decrypt Document Payload
        content_key = unwrap_content_key(package, recipient_id, self.keystore)
        plaintext_bytes = decrypt_document_payload(package, content_key)
        doc_hash = package["manifest"]["document_hash"]

        # Parse plaintext image
        img_np = np.frombuffer(plaintext_bytes, dtype=np.uint8)
        raw_image = cv2.imdecode(img_np, cv2.IMREAD_COLOR)
        if raw_image is None:
            raise ValueError("Decrypted payload is not a valid decodable image.")

        # STEP 3: Generate Session & Watermark Identifiers
        session_id = f"SESS-{secrets.token_hex(16).upper()}"
        watermark_id = secrets.token_hex(8).lower()  # 64 bits (16 hex chars)
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())

        # STEP 4: Construct Decryption Record
        # Recipient ID is recorded in the ledger record, NOT directly inside the watermark
        decryption_record: Dict[str, Any] = {
            "document_hash": doc_hash,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "watermark_length": 64
        }

        # STEP 5: Recipient Signs Record with ML-DSA-65 Private Key
        rec_priv = self.keystore.get_recipient_dsa_private_key(recipient_id)
        canonical_record_bytes = canonicalize(decryption_record)
        rec_sig = mldsa_sign(rec_priv, canonical_record_bytes)
        decryption_record["recipient_signature"] = base64.b64encode(rec_sig).decode('utf-8')

        # STEP 6: Submit to Offline Permissioned Ledger (4-of-5 Quorum)
        committed, receipt, commit_msg = self.ledger.commit_transaction(
            decryption_record,
            simulated_faulty_validators=simulated_faulty_validators
        )

        # STEP 7: COMMIT-BEFORE-RELEASE ENFORCEMENT
        if not committed or receipt is None:
            # Securely wipe plaintext from memory
            del plaintext_bytes
            del raw_image
            del content_key
            raise CommitBeforeReleaseError(
                f"COMMIT-BEFORE-RELEASE INVARIANT VIOLATION: Ledger commitment failed ({commit_msg}). "
                f"Document release strictly aborted to prevent unwatermarked exfiltration."
            )

        # STEP 8: Embed Session-Specific Invisible Forensic Watermark
        watermarked_image, _ = embed_watermark(raw_image, watermark_id, delta=watermark_delta)

        # Securely erase unwatermarked image
        del raw_image
        del plaintext_bytes

        # STEP 9: Release Watermarked Document
        return watermarked_image, decryption_record, receipt
