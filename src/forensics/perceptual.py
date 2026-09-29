"""
Document Identity and Perceptual Similarity Verification.
Clearly distinguishes between Exact Cryptographic Hash Matches and Perceptual Similarity Matches.
SIH Problem Statement 26237.
"""

import cv2
import numpy as np
from typing import Tuple, Optional, Dict, Any
from src.crypto.symmetric import sha3_256


def compute_dhash(img: np.ndarray, hash_size: int = 8) -> str:
    """
    Compute 64-bit difference hash (dHash) for perceptual image comparison.
    Invariant to brightness changes, scaling, and moderate compression.
    """
    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img.copy()

    # Resize to (hash_size + 1, hash_size)
    resized = cv2.resize(gray, (hash_size + 1, hash_size), interpolation=cv2.INTER_AREA)

    # Compare adjacent pixels horizontally
    diff = resized[:, 1:] > resized[:, :-1]
    bits = diff.flatten().astype(int)

    # Convert to 16-hex char string (64 bits)
    hex_str = ""
    for i in range(0, len(bits), 4):
        val = (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]
        hex_str += hex(val)[2:]
    return hex_str


def hamming_distance(hex1: str, hex2: str) -> int:
    """Compute Hamming distance between two hex hashes."""
    b1 = bin(int(hex1, 16))[2:].zfill(len(hex1) * 4)
    b2 = bin(int(hex2, 16))[2:].zfill(len(hex2) * 4)
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))


def compare_document_identity(
    candidate_img: np.ndarray,
    candidate_bytes: bytes,
    reference_hash: Optional[str] = None,
    reference_img: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    """
    Compare leaked candidate document against reference document or reference hash.

    Returns dictionary distinguishing:
    - EXACT_CRYPTOGRAPHIC_MATCH (True/False based on SHA3-256)
    - PERCEPTUAL_MATCH (True/False based on dHash / structural similarity)
    - IMPORTANT: Note that perceptual match is NOT cryptographic proof.
    """
    cand_sha3 = sha3_256(candidate_bytes)
    cand_dhash = compute_dhash(candidate_img)

    result = {
        "candidate_sha3_256": cand_sha3,
        "candidate_dhash": cand_dhash,
        "reference_sha3_256": reference_hash,
        "exact_cryptographic_match": False,
        "perceptual_similarity_match": False,
        "hamming_distance": None,
        "perceptual_confidence": 0.0,
        "match_type": "NO_MATCH",
        "forensic_distinction_note": (
            "NOTICE: Perceptual similarity indicates visual equivalence after transformation (compression, crop, resize) "
            "but does NOT constitute cryptographic proof of file identity."
        )
    }

    # 1. Exact Cryptographic Match
    if reference_hash and cand_sha3.lower() == reference_hash.lower():
        result["exact_cryptographic_match"] = True
        result["perceptual_similarity_match"] = True
        result["perceptual_confidence"] = 1.0
        result["match_type"] = "EXACT_CRYPTOGRAPHIC_MATCH"
        return result

    # 2. Perceptual Similarity Comparison (if reference image is provided)
    if reference_img is not None:
        ref_dhash = compute_dhash(reference_img)
        dist = hamming_distance(cand_dhash, ref_dhash)
        result["hamming_distance"] = dist
        # Threshold: dist <= 12 out of 64 bits indicates perceptual match under common transforms
        if dist <= 12:
            result["perceptual_similarity_match"] = True
            result["perceptual_confidence"] = round(1.0 - (dist / 64.0), 4)
            result["match_type"] = "PERCEPTUAL_SIMILARITY_MATCH"

    return result
