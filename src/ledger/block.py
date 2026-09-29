"""
Cryptographic Block and Header Structures for Offline Permissioned DLT.
SIH Problem Statement 26237.
"""

from typing import Dict, Any, List, Tuple, Optional
from src.crypto.canonical import canonicalize
from src.crypto.symmetric import sha3_256
from src.ledger.merkle import MerkleTree


class Block:
    """A cryptographically hash-chained block containing signed transactions and validator signatures."""

    def __init__(
        self,
        height: int,
        previous_hash: str,
        timestamp: int,
        merkle_root: str,
        transactions: List[Dict[str, Any]],
        validator_signatures: Optional[Dict[str, str]] = None,
        block_hash: Optional[str] = None
    ):
        self.header = {
            "height": height,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "merkle_root": merkle_root,
            "tx_count": len(transactions)
        }
        self.transactions = transactions
        self.validator_signatures = validator_signatures or {}
        self.block_hash = block_hash or self.compute_block_hash()

    def compute_block_hash(self) -> str:
        """Compute SHA3-256 hash of canonical block header."""
        return sha3_256(canonicalize(self.header))

    def get_signing_bytes(self) -> bytes:
        """Return canonical header bytes that validators sign."""
        return canonicalize(self.header)

    def add_validator_signature(self, validator_id: str, signature_b64: str) -> None:
        self.validator_signatures[validator_id] = signature_b64

    def to_dict(self) -> Dict[str, Any]:
        return {
            "height": self.header["height"],
            "previous_hash": self.header["previous_hash"],
            "timestamp": self.header["timestamp"],
            "merkle_root": self.header["merkle_root"],
            "tx_count": self.header["tx_count"],
            "block_hash": self.block_hash,
            "transactions": self.transactions,
            "validator_signatures": self.validator_signatures
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        return cls(
            height=data["height"],
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            merkle_root=data["merkle_root"],
            transactions=data["transactions"],
            validator_signatures=data.get("validator_signatures", {}),
            block_hash=data.get("block_hash")
        )

    def validate_structure(self) -> Tuple[bool, str]:
        """Verify internal consistency of header, hash, and Merkle root."""
        # 1. Verify block hash matches header
        computed_hash = self.compute_block_hash()
        if computed_hash != self.block_hash:
            return False, f"Block hash mismatch: computed {computed_hash}, got {self.block_hash}"

        # 2. Verify tx_count
        if len(self.transactions) != self.header["tx_count"]:
            return False, f"Transaction count mismatch: header {self.header['tx_count']}, actual {len(self.transactions)}"

        # 3. Verify Merkle root
        merkle_tree = MerkleTree(self.transactions)
        if merkle_tree.root != self.header["merkle_root"]:
            return False, f"Merkle root mismatch: computed {merkle_tree.root}, header {self.header['merkle_root']}"

        return True, "Valid"


def create_genesis_block(timestamp: int = 1727630000) -> Block:
    """Create the deterministic Genesis block at height 0."""
    genesis_tx = [{
        "type": "GENESIS",
        "description": "SIH Problem Statement 26237 Offline Permissioned Ledger Genesis",
        "timestamp": timestamp
    }]
    merkle_tree = MerkleTree(genesis_tx)
    return Block(
        height=0,
        previous_hash="0" * 64,
        timestamp=timestamp,
        merkle_root=merkle_tree.root,
        transactions=genesis_tx,
        validator_signatures={"SYSTEM": "GENESIS_ROOT"}
    )
