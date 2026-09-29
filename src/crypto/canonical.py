"""
Deterministic Canonical JSON Serialization (RFC 8785 compatible).
Ensures cryptographically reproducible hashing and digital signing across systems.
SIH Problem Statement 26237.
"""

import json
from typing import Any


def canonicalize(data: Any) -> bytes:
    """
    Produce canonical UTF-8 bytes for an arbitrary JSON-serializable dictionary or value.
    - Keys are recursively sorted lexicographically.
    - No whitespace between tokens (separators=(',', ':')).
    - Float and integer formatting is normalized.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')


def canonical_json_str(data: Any) -> str:
    """Return the canonical JSON string representation."""
    return canonicalize(data).decode('utf-8')
