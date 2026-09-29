"""
Unit and Integration Tests for Forensic Attribution, Perceptual Verification, and Evidence Bundles.
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
from src.distribution.package import create_distribution_package
from src.decryption.session import DecryptionSession
from src.forensics.trace import trace_document
from src.forensics.perceptual import compare_document_identity, compute_dhash
from src.evidence.bundle import save_evidence


class TestForensicsAndEvidence(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore = LocalKeystore(os.path.join(self.temp_dir, "keystore"))
        self.keystore.setup_demo_identities()
        self.ledger = PermissionedLedger(
            self.keystore,
            storage_dir=os.path.join(self.temp_dir, "ledger")
        )
        self.session_mgr = DecryptionSession(self.keystore, self.ledger)

        # Create canvas
        self.doc_img = np.ones((512, 512, 3), dtype=np.uint8) * 240
        cv2.putText(self.doc_img, "STRATEGIC DEFENCE PLAN 2026", (30, 80),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.75, (20, 20, 20), 2)
        cv2.rectangle(self.doc_img, (30, 100), (480, 450), (120, 120, 120), 2)
        _, enc_doc = cv2.imencode(".png", self.doc_img)
        self.doc_bytes = enc_doc.tobytes()

        self.ref_path = os.path.join(self.temp_dir, "reference.png")
        cv2.imwrite(self.ref_path, self.doc_img)

        # Distribute package
        self.package = create_distribution_package(
            self.doc_bytes,
            ["REC-047"],
            self.keystore,
            sender_id="SENDER-HQ"
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_end_to_end_trace_clean_document(self):
        # Decrypt for REC-047
        wm_doc, record, receipt = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047"
        )
        leaked_path = os.path.join(self.temp_dir, "clean_leak.png")
        cv2.imwrite(leaked_path, wm_doc)

        verified, bundle, report = trace_document(
            leaked_path,
            self.ledger,
            self.keystore,
            reference_image_path=self.ref_path
        )

        self.assertTrue(verified)
        self.assertEqual(bundle["attribution_status"], "VERIFIED")
        self.assertEqual(bundle["attribution_evidence"]["recipient_id"], "REC-047")
        self.assertEqual(bundle["attribution_evidence"]["watermark_id"], record["watermark_id"])
        self.assertTrue(bundle["verification_results"]["signature_valid"])
        self.assertTrue(bundle["verification_results"]["merkle_proof_valid"])
        self.assertTrue(bundle["verification_results"]["block_valid"])
        self.assertTrue(bundle["verification_results"]["validator_quorum_valid"])

    def test_trace_jpeg_attack_survival(self):
        wm_doc, record, _ = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047"
        )
        # Simulate severe JPEG compression (Q70)
        leaked_path = os.path.join(self.temp_dir, "jpeg70_leak.jpg")
        cv2.imwrite(leaked_path, wm_doc, [cv2.IMWRITE_JPEG_QUALITY, 70])

        verified, bundle, report = trace_document(
            leaked_path,
            self.ledger,
            self.keystore,
            reference_image_path=self.ref_path
        )

        self.assertTrue(verified)
        self.assertEqual(bundle["attribution_status"], "VERIFIED")
        self.assertEqual(bundle["attribution_evidence"]["recipient_id"], "REC-047")
        self.assertTrue(bundle["document_provenance"]["perceptual_similarity_match"])

    def test_trace_crop_attack_survival(self):
        wm_doc, record, _ = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047"
        )
        # 5% crop
        cropped = wm_doc[25:, 25:].copy()
        leaked_path = os.path.join(self.temp_dir, "cropped_leak.png")
        cv2.imwrite(leaked_path, cropped)

        verified, bundle, _ = trace_document(
            leaked_path,
            self.ledger,
            self.keystore,
            reference_image_path=self.ref_path
        )

        self.assertTrue(verified)
        self.assertEqual(bundle["attribution_evidence"]["recipient_id"], "REC-047")

    def test_trace_unwatermarked_document_fails(self):
        # Test original unwatermarked document
        verified, bundle, _ = trace_document(
            self.ref_path,
            self.ledger,
            self.keystore
        )

        self.assertFalse(verified)
        self.assertEqual(bundle["attribution_status"], "FAILED")
        self.assertFalse(bundle["verification_results"]["watermark_found"])

    def test_save_evidence_bundle(self):
        wm_doc, record, _ = self.session_mgr.decrypt_and_watermark(
            self.package,
            "REC-047"
        )
        leaked_path = os.path.join(self.temp_dir, "leak.png")
        cv2.imwrite(leaked_path, wm_doc)

        _, bundle, _ = trace_document(leaked_path, self.ledger, self.keystore)
        evidence_dir = os.path.join(self.temp_dir, "evidence")
        j_path, t_path = save_evidence(bundle, output_dir=evidence_dir)

        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))


if __name__ == "__main__":
    unittest.main()
