"""
NIST Standardized Post-Quantum Cryptography Primitives.
- ML-KEM-768 (FIPS 203) for Post-Quantum Key Encapsulation Mechanism
- ML-DSA-65 (FIPS 204) for Post-Quantum Digital Signatures
SIH Problem Statement 26237.
"""

import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ==============================================================================
# ML-KEM-768 (NIST FIPS 203)
# ==============================================================================

def generate_mlkem_keypair() -> Tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
    """Generate a fresh NIST FIPS 203 ML-KEM-768 private and public key pair."""
    priv = mlkem.MLKEM768PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def mlkem_encapsulate(public_key: mlkem.MLKEM768PublicKey) -> Tuple[bytes, bytes]:
    """
    Encapsulate a 32-byte shared secret against the recipient's ML-KEM-768 public key.
    Returns:
        shared_secret (bytes): 32-byte uniform random secret
        ciphertext (bytes): 1088-byte KEM capsule
    """
    shared_secret, ciphertext = public_key.encapsulate()
    return shared_secret, ciphertext


def mlkem_decapsulate(private_key: mlkem.MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    """
    Decapsulate the 1088-byte ciphertext using the recipient's ML-KEM-768 private key.
    Returns:
        shared_secret (bytes): 32-byte shared secret
    """
    return private_key.decapsulate(ciphertext)


def serialize_mlkem_public_key(public_key: mlkem.MLKEM768PublicKey) -> str:
    """Serialize ML-KEM public key to SubjectPublicKeyInfo PEM string."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def deserialize_mlkem_public_key(pem_str: str) -> mlkem.MLKEM768PublicKey:
    """Deserialize ML-KEM public key from SubjectPublicKeyInfo PEM string."""
    key = serialization.load_pem_public_key(pem_str.encode('utf-8'))
    if not isinstance(key, mlkem.MLKEM768PublicKey):
        raise TypeError(f"Expected MLKEM768PublicKey, got {type(key)}")
    return key


def serialize_mlkem_private_key(private_key: mlkem.MLKEM768PrivateKey) -> str:
    """Serialize ML-KEM private key to PKCS8 PEM string."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def deserialize_mlkem_private_key(pem_str: str) -> mlkem.MLKEM768PrivateKey:
    """Deserialize ML-KEM private key from PKCS8 PEM string."""
    key = serialization.load_pem_private_key(pem_str.encode('utf-8'), password=None)
    if not isinstance(key, mlkem.MLKEM768PrivateKey):
        raise TypeError(f"Expected MLKEM768PrivateKey, got {type(key)}")
    return key


# ==============================================================================
# ML-DSA-65 (NIST FIPS 204)
# ==============================================================================

def generate_mldsa_keypair() -> Tuple[mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey]:
    """Generate a fresh NIST FIPS 204 ML-DSA-65 private and public key pair."""
    priv = mldsa.MLDSA65PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def mldsa_sign(private_key: mldsa.MLDSA65PrivateKey, message: bytes) -> bytes:
    """Sign an arbitrary message using ML-DSA-65 private key."""
    return private_key.sign(message)


def mldsa_verify(public_key: mldsa.MLDSA65PublicKey, signature: bytes, message: bytes) -> bool:
    """
    Verify an ML-DSA-65 digital signature against a message.
    Returns True if valid, False otherwise. Never throws on signature mismatch.
    """
    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def serialize_mldsa_public_key(public_key: mldsa.MLDSA65PublicKey) -> str:
    """Serialize ML-DSA public key to SubjectPublicKeyInfo PEM string."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def deserialize_mldsa_public_key(pem_str: str) -> mldsa.MLDSA65PublicKey:
    """Deserialize ML-DSA public key from SubjectPublicKeyInfo PEM string."""
    key = serialization.load_pem_public_key(pem_str.encode('utf-8'))
    if not isinstance(key, mldsa.MLDSA65PublicKey):
        raise TypeError(f"Expected MLDSA65PublicKey, got {type(key)}")
    return key


def serialize_mldsa_private_key(private_key: mldsa.MLDSA65PrivateKey) -> str:
    """Serialize ML-DSA private key to PKCS8 PEM string."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def deserialize_mldsa_private_key(pem_str: str) -> mldsa.MLDSA65PrivateKey:
    """Deserialize ML-DSA private key from PKCS8 PEM string."""
    key = serialization.load_pem_private_key(pem_str.encode('utf-8'), password=None)
    if not isinstance(key, mldsa.MLDSA65PrivateKey):
        raise TypeError(f"Expected MLDSA65PrivateKey, got {type(key)}")
    return key
