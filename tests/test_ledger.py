"""
Unit and Adversarial Tests for Offline Permissioned Ledger and 4-of-5 Consensus.
SIH Problem Statement 26237.
"""

import os
import shutil
import tempfile
import unittest
import base64
from src.identity.keystore import LocalKeystore
from src.crypto.canonical import canonicalize
from src.crypto.pqc import mldsa_sign
from src.crypto.symmetric import sha3_256
from src.ledger.merkle import MerkleTree, verify_merkle_proof
from src.ledger.block import Block, create_genesis_block
from src.ledger.ledger import PermissionedLedger, QUORUM_THRESHOLD, TOTAL_VALIDATORS


class TestLedgerAndConsensus(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore = LocalKeystore(os.path.join(self.temp_dir, "keystore"))
        self.keystore.setup_demo_identities()
        self.ledger = PermissionedLedger(
            self.keystore,
            storage_dir=os.path.join(self.temp_dir, "ledger")
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_tx(self, recipient_id: str = "REC-047", wm_id: str = "a1b2c3d4e5f60718") -> dict:
        tx = {
            "document_hash": sha3_256(b"sample_classified_document"),
            "recipient_id": recipient_id,
            "session_id": "sess-test-9999",
            "watermark_id": wm_id,
            "timestamp": 1727632000,
            "nonce": "nonce-test-1234",
            "watermark_length": 64
        }
        priv_key = self.keystore.get_recipient_dsa_private_key(recipient_id)
        sig = mldsa_sign(priv_key, canonicalize(tx))
        tx["recipient_signature"] = base64.b64encode(sig).decode('utf-8')
        return tx

    # --- Merkle Tree Tests ---
    def test_merkle_tree_construction_and_root(self):
        items = ["tx1", "tx2", "tx3", "tx4"]
        tree1 = MerkleTree(items)
        tree2 = MerkleTree(items)
        self.assertEqual(tree1.root, tree2.root)
        self.assertEqual(len(tree1.root), 64)

    def test_merkle_inclusion_proof_validity(self):
        items = [{"id": 1, "data": "first"}, {"id": 2, "data": "second"}, {"id": 3, "data": "third"}]
        tree = MerkleTree(items)

        for idx, item in enumerate(items):
            proof = tree.get_proof(idx)
            self.assertTrue(verify_merkle_proof(item, proof, tree.root))

    def test_merkle_proof_tampered_item_rejection(self):
        items = [{"id": 1, "data": "authentic"}, {"id": 2, "data": "authentic_2"}]
        tree = MerkleTree(items)
        proof = tree.get_proof(0)

        # Altering item must fail proof verification
        tampered_item = {"id": 1, "data": "forged_data"}
        self.assertFalse(verify_merkle_proof(tampered_item, proof, tree.root))

    # --- Block Structure Tests ---
    def test_block_structure_and_hash(self):
        genesis = create_genesis_block()
        valid, msg = genesis.validate_structure()
        self.assertTrue(valid, msg)
        self.assertEqual(genesis.header["height"], 0)

    # --- 4-of-5 Consensus Quorum Tests ---
    def test_commit_transaction_full_quorum(self):
        tx = self._create_sample_tx("REC-047", "deadbeef00000001")
        success, receipt, msg = self.ledger.commit_transaction(tx)

        self.assertTrue(success, msg)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["block_height"], 1)
        self.assertEqual(receipt["quorum_count"], "5/5")
        self.assertEqual(self.ledger.height, 1)

    def test_commit_transaction_tolerates_one_byzantine_validator(self):
        # Assumption: At most 1 faulty/Byzantine node out of 5
        # Simulate VAL-05 offline/faulty
        tx = self._create_sample_tx("REC-001", "deadbeef00000002")
        success, receipt, msg = self.ledger.commit_transaction(
            tx,
            simulated_faulty_validators=["VAL-05"]
        )

        self.assertTrue(success, msg)
        self.assertEqual(receipt["quorum_count"], "4/5")
        self.assertNotIn("VAL-05", receipt["validator_signatures"])
        self.assertEqual(self.ledger.height, 1)

    def test_commit_transaction_fails_if_two_validators_faulty(self):
        # 4-of-5 quorum rule: if 2 validators fail (only 3 available), commit MUST fail
        tx = self._create_sample_tx("REC-002", "deadbeef00000003")
        success, receipt, msg = self.ledger.commit_transaction(
            tx,
            simulated_faulty_validators=["VAL-04", "VAL-05"]
        )

        self.assertFalse(success)
        self.assertIsNone(receipt)
        self.assertIn("Quorum failure", msg)
        self.assertEqual(self.ledger.height, 0)  # Height remains at 0 (genesis only)

    def test_reject_invalid_transaction_signature(self):
        tx = self._create_sample_tx("REC-047", "deadbeef00000004")
        # Tamper with recipient signature
        tx["recipient_signature"] = base64.b64encode(b"invalid_signature" * 50).decode('utf-8')

        success, receipt, msg = self.ledger.commit_transaction(tx)
        self.assertFalse(success)
        self.assertIn("Invalid ML-DSA-65 signature", msg)
        self.assertEqual(self.ledger.height, 0)

    # --- Query and Chain Integrity Tests ---
    def test_lookup_by_watermark_id_and_merkle_verification(self):
        wm_target = "cafebeef12345678"
        tx = self._create_sample_tx("REC-047", wm_target)
        success, receipt, _ = self.ledger.commit_transaction(tx)
        self.assertTrue(success)

        result = self.ledger.lookup_by_watermark_id(wm_target)
        self.assertIsNotNone(result)
        found_tx, block, proof = result

        self.assertEqual(found_tx["watermark_id"], wm_target)
        self.assertEqual(found_tx["recipient_id"], "REC-047")
        self.assertTrue(verify_merkle_proof(found_tx, proof, block.header["merkle_root"]))

    def test_full_chain_integrity_verification(self):
        # Commit two transactions across two blocks
        tx1 = self._create_sample_tx("REC-001", "wm00000000000001")
        tx2 = self._create_sample_tx("REC-047", "wm00000000000002")

        self.ledger.commit_transaction(tx1)
        self.ledger.commit_transaction(tx2, simulated_faulty_validators=["VAL-02"])

        self.assertEqual(self.ledger.height, 2)
        valid_chain, reason = self.ledger.verify_chain_integrity()
        self.assertTrue(valid_chain, reason)


if __name__ == "__main__":
    unittest.main()
