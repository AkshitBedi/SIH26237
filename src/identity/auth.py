"""
Cryptographic Recipient Authentication via ML-DSA-65 Challenge-Response.
Eliminates passwords and shared secrets; uses pure post-quantum asymmetric identity.
SIH Problem Statement 26237.
"""

import time
import secrets
import base64
from typing import Dict, Any, Tuple
from src.crypto.canonical import canonicalize
from src.crypto.pqc import mldsa_sign, mldsa_verify
from src.identity.keystore import LocalKeystore


def create_auth_challenge(recipient_id: str, keystore: LocalKeystore, ttl_seconds: int = 300) -> Dict[str, Any]:
    """
    Generate a cryptographic challenge for an authenticating recipient.
    """
    # Ensure recipient exists in the keystore registry
    registry = keystore.get_public_registry()
    if recipient_id not in registry.get("recipients", {}):
        raise KeyError(f"Recipient {recipient_id} is not registered in the keystore.")

    challenge = {
        "challenge_id": secrets.token_hex(16),
        "recipient_id": recipient_id,
        "timestamp": int(time.time()),
        "ttl_seconds": ttl_seconds,
        "nonce": secrets.token_hex(16)
    }
    return challenge


def respond_to_challenge(challenge: Dict[str, Any], keystore: LocalKeystore) -> Dict[str, Any]:
    """
    Recipient signs the canonical challenge using their local ML-DSA-65 private key.
    """
    recipient_id = challenge["recipient_id"]
    priv_key = keystore.get_recipient_dsa_private_key(recipient_id)

    canonical_bytes = canonicalize(challenge)
    signature = mldsa_sign(priv_key, canonical_bytes)
    sig_b64 = base64.b64encode(signature).decode('utf-8')

    return {
        "challenge": challenge,
        "recipient_id": recipient_id,
        "signature": sig_b64
    }


def verify_auth_response(
    auth_response: Dict[str, Any],
    keystore: LocalKeystore,
    max_drift_seconds: int = 600
) -> Tuple[bool, str]:
    """
    Server/Validator verifies recipient's ML-DSA-65 signature on the challenge.
    Returns:
        (is_valid, reason_str)
    """
    try:
        challenge = auth_response["challenge"]
        recipient_id = auth_response["recipient_id"]
        sig_b64 = auth_response["signature"]

        # Check timestamp drift
        now = int(time.time())
        issued_at = challenge.get("timestamp", 0)
        ttl = challenge.get("ttl_seconds", 300)
        if abs(now - issued_at) > (ttl + max_drift_seconds):
            return False, "Challenge expired or excessive clock drift"

        # Fetch registered public key
        pub_key = keystore.get_recipient_dsa_public_key(recipient_id)

        canonical_bytes = canonicalize(challenge)
        sig_bytes = base64.b64decode(sig_b64)

        if not mldsa_verify(pub_key, sig_bytes, canonical_bytes):
            return False, "Invalid ML-DSA-65 signature on challenge"

        return True, "Authenticated"
    except Exception as e:
        return False, f"Authentication error: {str(e)}"
