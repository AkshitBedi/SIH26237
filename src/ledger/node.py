"""
Permissioned Validator Node Logic.
Enforces block verification, transaction signature validation, and ML-DSA-65 block signing.
SIH Problem Statement 26237.
"""

import base64
from typing import Dict, Any, List, Tuple, Optional
from src.crypto.canonical import canonicalize
from src.crypto.pqc import mldsa_sign, mldsa_verify
from src.identity.keystore import LocalKeystore
from src.ledger.block import Block, create_genesis_block


REQUIRED_TX_FIELDS = [
    "document_hash",
    "recipient_id",
    "session_id",
    "watermark_id",
    "timestamp",
    "nonce",
    "recipient_signature"
]


class ValidatorNode:
    """Individual permissioned validator node."""

    def __init__(self, validator_id: str, keystore: LocalKeystore):
        self.validator_id = validator_id
        self.keystore = keystore
        self.chain: List[Block] = [create_genesis_block()]

    @property
    def current_height(self) -> int:
        return self.chain[-1].header["height"]

    @property
    def last_block_hash(self) -> str:
        return self.chain[-1].block_hash

    def validate_transaction(self, tx: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate transaction format and recipient ML-DSA-65 digital signature.
        """
        # 1. Field validation
        for field in REQUIRED_TX_FIELDS:
            if field not in tx:
                return False, f"Missing required transaction field: {field}"

        recipient_id = tx["recipient_id"]
        sig_b64 = tx["recipient_signature"]

        # 2. Keystore lookup
        try:
            pub_key = self.keystore.get_recipient_dsa_public_key(recipient_id)
        except Exception as e:
            return False, f"Failed to retrieve public key for {recipient_id}: {str(e)}"

        # 3. Canonical signature verification
        # The signature covers the record with the signature field itself excluded
        unsigned_record = {k: v for k, v in tx.items() if k != "recipient_signature"}
        canonical_bytes = canonicalize(unsigned_record)

        try:
            sig_bytes = base64.b64decode(sig_b64)
            if not mldsa_verify(pub_key, sig_bytes, canonical_bytes):
                return False, f"Invalid ML-DSA-65 signature for recipient {recipient_id}"
        except Exception as e:
            return False, f"Signature verification exception: {str(e)}"

        return True, "Valid"

    def evaluate_and_sign_block(self, block: Block) -> Tuple[bool, Optional[str], str]:
        """
        Evaluate a candidate block against local chain and transactions.
        If accepted, returns (True, base64_signature, "Accepted").
        """
        # 1. Height check
        expected_height = self.current_height + 1
        if block.header["height"] != expected_height:
            return False, None, f"Height mismatch: expected {expected_height}, got {block.header['height']}"

        # 2. Previous hash check
        if block.header["previous_hash"] != self.last_block_hash:
            return False, None, f"Previous hash mismatch: expected {self.last_block_hash}, got {block.header['previous_hash']}"

        # 3. Structure check (block hash & Merkle root)
        valid_struct, reason = block.validate_structure()
        if not valid_struct:
            return False, None, f"Structure validation failed: {reason}"

        # 4. Transaction validation
        for tx in block.transactions:
            tx_valid, tx_reason = self.validate_transaction(tx)
            if not tx_valid:
                return False, None, f"Transaction rejected in block: {tx_reason}"

        # 5. Sign canonical block header with validator's ML-DSA-65 private key
        try:
            priv_key = self.keystore.get_validator_dsa_private_key(self.validator_id)
            signing_bytes = block.get_signing_bytes()
            sig = mldsa_sign(priv_key, signing_bytes)
            sig_b64 = base64.b64encode(sig).decode('utf-8')
            return True, sig_b64, "Accepted"
        except Exception as e:
            return False, None, f"Validator signing failed: {str(e)}"

    def commit_block(
        self,
        block: Block,
        authorized_validators: List[str],
        quorum_threshold: int = 4
    ) -> Tuple[bool, str]:
        """
        Commit candidate block if at least quorum_threshold valid validator signatures exist.
        """
        valid_signatures = 0
        signing_bytes = block.get_signing_bytes()

        for val_id, sig_b64 in block.validator_signatures.items():
            if val_id not in authorized_validators:
                continue
            try:
                val_pub = self.keystore.get_validator_dsa_public_key(val_id)
                sig_bytes = base64.b64decode(sig_b64)
                if mldsa_verify(val_pub, sig_bytes, signing_bytes):
                    valid_signatures += 1
            except Exception:
                continue

        if valid_signatures < quorum_threshold:
            return False, f"Insufficient validator quorum: {valid_signatures}/{quorum_threshold} required."

        # Verify block matches chain continuity before appending
        if block.header["previous_hash"] != self.last_block_hash:
            return False, "Cannot commit: previous hash mismatch with local tip."

        self.chain.append(block)
        return True, f"Committed block #{block.header['height']} with {valid_signatures} validator signatures."
