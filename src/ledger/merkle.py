"""
Cryptographic Merkle Tree and Offline Inclusion Proofs using SHA3-256.
SIH Problem Statement 26237.
"""

from typing import List, Dict, Any, Tuple
from src.crypto.symmetric import sha3_256, sha3_256_bytes
from src.crypto.canonical import canonicalize


def hash_leaf(data_or_hash: str) -> str:
    """Hash a leaf using SHA3-256 with domain separation prefix b'LEAF:'."""
    payload = b"LEAF:" + data_or_hash.encode('utf-8')
    return sha3_256(payload)


def hash_internal_node(left_hash: str, right_hash: str) -> str:
    """Hash internal Merkle node with domain separation prefix b'NODE:'."""
    payload = b"NODE:" + left_hash.encode('utf-8') + b":" + right_hash.encode('utf-8')
    return sha3_256(payload)


class MerkleTree:
    """Binary Merkle Tree built with SHA3-256."""

    def __init__(self, items: List[Any]):
        self.raw_items = items
        self.leaf_hashes: List[str] = []
        for item in items:
            if isinstance(item, dict):
                item_hash = sha3_256(canonicalize(item))
            elif isinstance(item, str):
                item_hash = item
            elif isinstance(item, bytes):
                item_hash = sha3_256(item)
            else:
                item_hash = sha3_256(str(item).encode('utf-8'))
            self.leaf_hashes.append(hash_leaf(item_hash))

        self.levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaf_hashes:
            empty_root = sha3_256(b"EMPTY_MERKLE_TREE")
            self.levels = [[empty_root]]
            return

        current_level = self.leaf_hashes.copy()
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last odd leaf
                    right = left
                parent = hash_internal_node(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0] if self.levels else sha3_256(b"EMPTY_MERKLE_TREE")

    def get_proof(self, index: int) -> Dict[str, Any]:
        """
        Generate an offline Merkle inclusion proof for the leaf at `index`.
        """
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError(f"Index {index} out of range for Merkle tree of size {len(self.leaf_hashes)}")

        target_leaf = self.leaf_hashes[index]
        proof_path: List[Dict[str, str]] = []

        cur_idx = index
        for level in self.levels[:-1]:
            if cur_idx % 2 == 0:
                # Target is left child, sibling is right
                sibling_idx = cur_idx + 1 if cur_idx + 1 < len(level) else cur_idx
                position = "right"
            else:
                # Target is right child, sibling is left
                sibling_idx = cur_idx - 1
                position = "left"

            sibling_hash = level[sibling_idx]
            proof_path.append({
                "position": position,
                "hash": sibling_hash
            })
            cur_idx = cur_idx // 2

        return {
            "leaf_index": index,
            "leaf_hash": target_leaf,
            "root": self.root,
            "path": proof_path
        }


def verify_merkle_proof(item: Any, proof: Dict[str, Any], expected_root: str) -> bool:
    """
    Verify an offline Merkle inclusion proof against an expected block Merkle root.
    """
    try:
        if isinstance(item, dict):
            item_hash = sha3_256(canonicalize(item))
        elif isinstance(item, str):
            item_hash = item
        elif isinstance(item, bytes):
            item_hash = sha3_256(item)
        else:
            item_hash = sha3_256(str(item).encode('utf-8'))

        computed_leaf = hash_leaf(item_hash)
        if computed_leaf != proof.get("leaf_hash"):
            return False

        current_hash = computed_leaf
        for step in proof.get("path", []):
            pos = step["position"]
            sib_hash = step["hash"]
            if pos == "right":
                current_hash = hash_internal_node(current_hash, sib_hash)
            elif pos == "left":
                current_hash = hash_internal_node(sib_hash, current_hash)
            else:
                return False

        return current_hash == expected_root and expected_root == proof.get("root")
    except Exception:
        return False
