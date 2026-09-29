"""
Offline Permissioned Ledger Manager.
Coordinates 5 validator nodes, enforces 4-of-5 quorum consensus, Merkle proofs, and state persistence.
SIH Problem Statement 26237.
"""

import os
import json
import time
from typing import Dict, Any, List, Tuple, Optional
from src.identity.keystore import LocalKeystore
from src.ledger.block import Block, create_genesis_block
from src.ledger.node import ValidatorNode
from src.ledger.merkle import MerkleTree, verify_merkle_proof
from src.crypto.pqc import mldsa_verify
import base64

TOTAL_VALIDATORS = 5
QUORUM_THRESHOLD = 4


class PermissionedLedger:
    """Manages the 5-validator permissioned ledger with 4-of-5 commit quorum."""

    def __init__(self, keystore: LocalKeystore, storage_dir: str = "data/ledger"):
        self.keystore = keystore
        self.storage_dir = os.path.abspath(storage_dir)
        self.ledger_file = os.path.join(self.storage_dir, "blockchain.json")
        os.makedirs(self.storage_dir, exist_ok=True)

        self.validator_ids = [f"VAL-0{i}" for i in range(1, TOTAL_VALIDATORS + 1)]
        self.validators: Dict[str, ValidatorNode] = {}
        for v_id in self.validator_ids:
            self.validators[v_id] = ValidatorNode(v_id, self.keystore)

        self._load_from_storage()

    def _load_from_storage(self) -> None:
        """Load blockchain from disk if available."""
        if os.path.exists(self.ledger_file):
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    blocks_data = json.load(f)
                chain = [Block.from_dict(b) for b in blocks_data]
                # Sync all validators
                for v in self.validators.values():
                    v.chain = [Block.from_dict(b) for b in blocks_data]
            except Exception:
                pass

    def _save_to_storage(self) -> None:
        """Persist current canonical chain to disk."""
        # Use primary validator chain as canonical
        primary = self.validators[self.validator_ids[0]]
        chain_dicts = [b.to_dict() for b in primary.chain]
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(chain_dicts, f, indent=2)

    @property
    def height(self) -> int:
        return self.validators[self.validator_ids[0]].current_height

    @property
    def tip_hash(self) -> str:
        return self.validators[self.validator_ids[0]].last_block_hash

    def commit_transaction(
        self,
        transaction: Dict[str, Any],
        simulated_faulty_validators: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Propose a new block containing the transaction and commit via 4-of-5 validator quorum.

        Args:
            transaction: Signed decryption record
            simulated_faulty_validators: Optional list of validator IDs simulating offline/Byzantine state

        Returns:
            (success: bool, receipt: Optional[dict], message: str)
        """
        faulty = set(simulated_faulty_validators or [])

        # Step 1: Pre-validate transaction on primary validator
        primary = self.validators[self.validator_ids[0]]
        tx_valid, reason = primary.validate_transaction(transaction)
        if not tx_valid:
            return False, None, f"Transaction invalid: {reason}"

        # Step 2: Assemble proposed block
        next_height = self.height + 1
        prev_hash = self.tip_hash
        timestamp = transaction.get("timestamp", int(time.time()))

        tx_list = [transaction]
        merkle_tree = MerkleTree(tx_list)

        candidate_block = Block(
            height=next_height,
            previous_hash=prev_hash,
            timestamp=timestamp,
            merkle_root=merkle_tree.root,
            transactions=tx_list
        )

        # Step 3: Gather validator signatures (Consensus phase)
        collected_signatures: Dict[str, str] = {}
        for v_id, node in self.validators.items():
            if v_id in faulty:
                continue  # Faulty/offline validator does not sign

            accepted, sig_b64, reason = node.evaluate_and_sign_block(candidate_block)
            if accepted and sig_b64:
                collected_signatures[v_id] = sig_b64

        candidate_block.validator_signatures = collected_signatures

        # Step 4: Enforce 4-of-5 Quorum Rule
        if len(collected_signatures) < QUORUM_THRESHOLD:
            return False, None, (
                f"Quorum failure: collected {len(collected_signatures)}/{QUORUM_THRESHOLD} "
                f"required validator signatures (Faulty: {list(faulty)})."
            )

        # Step 5: Commit block on all active validators
        commit_success_count = 0
        for v_id, node in self.validators.items():
            if v_id in faulty:
                continue
            committed, c_reason = node.commit_block(
                candidate_block,
                self.validator_ids,
                QUORUM_THRESHOLD
            )
            if committed:
                commit_success_count += 1

        if commit_success_count < QUORUM_THRESHOLD:
            return False, None, "Commit phase failed across validator nodes."

        self._save_to_storage()

        # Generate inclusion proof for the transaction in this block (index 0)
        merkle_proof = merkle_tree.get_proof(0)

        receipt = {
            "status": "COMMITTED",
            "block_height": candidate_block.header["height"],
            "block_hash": candidate_block.block_hash,
            "previous_hash": candidate_block.header["previous_hash"],
            "timestamp": candidate_block.header["timestamp"],
            "merkle_root": candidate_block.header["merkle_root"],
            "merkle_proof": merkle_proof,
            "validator_signatures": collected_signatures,
            "quorum_count": f"{len(collected_signatures)}/{TOTAL_VALIDATORS}",
            "transaction_watermark_id": transaction.get("watermark_id")
        }

        return True, receipt, f"Block #{next_height} committed with {len(collected_signatures)}/{TOTAL_VALIDATORS} validator signatures."

    def lookup_by_watermark_id(self, watermark_id: str) -> Optional[Tuple[Dict[str, Any], Block, Dict[str, Any]]]:
        """
        Query the offline ledger for a transaction matching watermark_id.
        Returns:
            (transaction, block, merkle_proof) or None if not found
        """
        primary = self.validators[self.validator_ids[0]]
        for block in primary.chain:
            for idx, tx in enumerate(block.transactions):
                if tx.get("watermark_id") == watermark_id:
                    # Generate Merkle proof for this leaf in the block
                    tree = MerkleTree(block.transactions)
                    proof = tree.get_proof(idx)
                    return tx, block, proof
        return None

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        """
        Independently verify full cryptographic integrity of the blockchain:
        - Genesis validity
        - Block hash chaining (previous_hash matches prior block_hash)
        - Merkle root matches transactions
        - Block hash matches header
        - 4-of-5 valid validator signatures on every non-genesis block
        """
        primary = self.validators[self.validator_ids[0]]
        chain = primary.chain

        if not chain or chain[0].header["height"] != 0:
            return False, "Invalid or missing genesis block."

        for i in range(1, len(chain)):
            prev_block = chain[i - 1]
            curr_block = chain[i]

            # 1. Height continuity
            if curr_block.header["height"] != prev_block.header["height"] + 1:
                return False, f"Height discontinuity at block #{curr_block.header['height']}"

            # 2. Previous hash chaining
            if curr_block.header["previous_hash"] != prev_block.block_hash:
                return False, f"Broken hash chain at block #{curr_block.header['height']}"

            # 3. Structure check
            valid_struct, reason = curr_block.validate_structure()
            if not valid_struct:
                return False, f"Invalid structure in block #{curr_block.header['height']}: {reason}"

            # 4. Validator signature quorum check
            valid_sigs = 0
            signing_bytes = curr_block.get_signing_bytes()
            for v_id, sig_b64 in curr_block.validator_signatures.items():
                if v_id not in self.validator_ids:
                    continue
                try:
                    val_pub = self.keystore.get_validator_dsa_public_key(v_id)
                    sig_bytes = base64.b64decode(sig_b64)
                    if mldsa_verify(val_pub, sig_bytes, signing_bytes):
                        valid_sigs += 1
                except Exception:
                    continue

            if valid_sigs < QUORUM_THRESHOLD:
                return False, f"Block #{curr_block.header['height']} has insufficient quorum: {valid_sigs}/{QUORUM_THRESHOLD}"

        return True, f"Verified all {len(chain)} blocks. Hash chain, Merkle roots, and 4/5 validator quorum valid."
