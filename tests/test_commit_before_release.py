"""
Tests for Document Distribution, Decryption Session, and Commit-Before-Release Invariant.
SIH Problem Statement 26237.
"""

import os
import shutil
import tempfile
import unittest
import cv2
import numpy as np

from src.identity.keystore import LocalKeystore
from src.ledger.ledger import PermissionedLedger
from src.distribution.package import (
    create_distribution_package,
    save_package,
    load_package,
    unwrap_content_key,
    decrypt_document_payload,
)
from src.decryption.session import DecryptionSession, CommitBeforeReleaseError
from src.watermark.transform import extract_watermark


class TestCommitBeforeRelease(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore = LocalKeystore(os.path.join(self.temp_dir, "keystore"))
        self.keystore.setup_demo_identities()
        self.ledger = PermissionedLedger(
            self.keystore,
            storage_dir=os.path.join(self.temp_dir, "ledger")
        )
        self.session_mgr = DecryptionSession(self.keystore, self.ledger)

        # Create a sample document image (300x300)
        self.doc_img = np.ones((300, 300, 3), dtype=np.uint8) * 245
        cv2.putText(self.doc_img, "OPERATIONAL SECURITY MEMO", (20, 60),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (10, 10, 10), 1)
        cv2.rectangle(self.doc_img, (20, 80), (280, 260), (120, 120, 120), 2)
        _, enc_doc = cv2.imencode(".png", self.doc_img)
        self.doc_bytes = enc_doc.tobytes()

        # Multi-recipient package
        self.recipients = ["REC-001", "REC-002", "REC-047"]
        self.package = create_distribution_package(
            self.doc_bytes,
            self.recipients,
            self.keystore,
            sender_id="SENDER-HQ",
            filename="memo.png"
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_multi_recipient_package_creation(self):
        self.assertEqual(self.package["manifest"]["recipient_count"], 3)
        self.assertIn("REC-001", self.package["recipient_capsules"])
        self.assertIn("REC-002", self.package["recipient_capsules"])
        self.assertIn("REC-047", self.package["recipient_capsules"])

        # Unwrapping should succeed for all three recipients
        for r_id in self.recipients:
            key = unwrap_content_key(self.package, r_id, self.keystore)
            dec = decrypt_document_payload(self.package, key)
            self.assertEqual(dec, self.doc_bytes)

    def test_unauthorized_recipient_rejected(self):
        with self.assertRaises(PermissionError):
            unwrap_content_key(self.package, "REC-UNKNOWN", self.keystore)

    def test_successful_commit_before_release(self):
        initial_height = self.ledger.height
        wm_doc, record, receipt = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047"
        )

        # 1. Verification of document release
        self.assertIsNotNone(wm_doc)
        self.assertEqual(wm_doc.shape, self.doc_img.shape)

        # 2. Verification of ledger commitment
        self.assertEqual(self.ledger.height, initial_height + 1)
        self.assertEqual(receipt["status"], "COMMITTED")
        self.assertEqual(receipt["quorum_count"], "5/5")
        self.assertIn("VAL-01", receipt["validator_signatures"])

        # 3. Verification of decryption record
        self.assertEqual(record["recipient_id"], "REC-047")
        self.assertEqual(record["watermark_id"], receipt["transaction_watermark_id"])

        # 4. Verify embedded watermark matches record
        ext_wm_id, ber, crc_valid, _ = extract_watermark(wm_doc, search_shifts=False)
        self.assertEqual(ext_wm_id, record["watermark_id"])
        self.assertTrue(crc_valid)

    def test_watermark_uniqueness_per_session_same_recipient(self):
        # Recipient REC-047 decrypts twice
        _, record1, _ = self.session_mgr.decrypt_and_watermark(self.package, "REC-047")
        _, record2, _ = self.session_mgr.decrypt_and_watermark(self.package, "REC-047")

        self.assertNotEqual(record1["session_id"], record2["session_id"])
        self.assertNotEqual(record1["watermark_id"], record2["watermark_id"])
        self.assertNotEqual(record1["nonce"], record2["nonce"])

    def test_commit_before_release_aborts_on_insufficient_quorum(self):
        # INVARIANT TEST: Simulate 2 faulty validators (VAL-04, VAL-05)
        # Quorum rule requires 4-of-5; only 3 sign.
        # MUST raise CommitBeforeReleaseError and MUST NOT release document!
        initial_height = self.ledger.height

        with self.assertRaises(CommitBeforeReleaseError) as ctx:
            self.session_mgr.decrypt_and_watermark(
                self.package,
                "REC-047",
                simulated_faulty_validators=["VAL-04", "VAL-05"]
            )

        self.assertIn("COMMIT-BEFORE-RELEASE INVARIANT VIOLATION", str(ctx.exception))
        # Verify ledger was not mutated
        self.assertEqual(self.ledger.height, initial_height)

    def test_commit_before_release_succeeds_with_one_faulty_validator(self):
        # Byzantine assumption: at most 1 faulty validator (VAL-05)
        # 4 of 5 sign -> commit succeeds, document released
        initial_height = self.ledger.height
        wm_doc, record, receipt = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047",
            simulated_faulty_validators=["VAL-05"]
        )

        self.assertIsNotNone(wm_doc)
        self.assertEqual(receipt["quorum_count"], "4/5")
        self.assertEqual(self.ledger.height, initial_height + 1)


if __name__ == "__main__":
    unittest.main()
