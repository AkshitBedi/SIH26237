"""
Symmetric Cryptography and Hashing.
Implements NIST FIPS 202 SHA3-256 and NIST SP 800-38D AES-256-GCM.
SIH Problem Statement 26237.
"""

import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha3_256_bytes(data: bytes) -> bytes:
    """Compute NIST FIPS 202 SHA3-256 hash as raw 32 bytes."""
    return hashlib.sha3_256(data).digest()


def sha3_256(data: bytes) -> str:
    """Compute NIST FIPS 202 SHA3-256 hash as 64-character hexadecimal string."""
    return hashlib.sha3_256(data).hexdigest()


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure random 256-bit (32 bytes) AES key."""
    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generate a standard 96-bit (12 bytes) initialization vector for AES-GCM."""
    return os.urandom(12)


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    nonce: Optional[bytes] = None,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns:
        ciphertext (bytes): The encrypted payload without the tag.
        nonce (bytes): The 12-byte IV.
        tag (bytes): The 16-byte authentication tag.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")

    if nonce is None:
        nonce = generate_nonce()
    elif len(nonce) != 12:
        raise ValueError(f"AES-GCM requires a 12-byte nonce, got {len(nonce)}")

    aesgcm = AESGCM(key)
    # cryptography's AESGCM.encrypt appends the 16-byte tag to ciphertext
    full_ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = full_ct[:-16]
    tag = full_ct[-16:]

    return ciphertext, nonce, tag


def decrypt_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypt and authenticate ciphertext using AES-256-GCM.
    Raises InvalidTag if ciphertext, tag, or associated_data was tampered with.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"AES-GCM requires a 12-byte nonce, got {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(f"AES-GCM requires a 16-byte tag, got {len(tag)}")

    full_ct = ciphertext + tag
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, full_ct, associated_data)
