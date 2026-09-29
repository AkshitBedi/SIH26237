"""
Unit and Integration Tests for Watermark Module.
SIH Problem Statement 26237.
"""

import unittest
import secrets
import cv2
import numpy as np
from src.watermark.ecc import (
    encode_payload,
    decode_payload,
    crc16_ccitt,
    hex_to_bits,
    bits_to_hex,
    PACKET_LENGTH,
)
from src.watermark.transform import embed_watermark, extract_watermark
from src.watermark.metrics import calculate_ber, calculate_psnr, calculate_ssim


class TestWatermarkModule(unittest.TestCase):

    def setUp(self):
        # Create a basic 256x256 test canvas
        self.test_img = np.ones((256, 256, 3), dtype=np.uint8) * 240
        cv2.putText(self.test_img, "SIH TEST DOCUMENT", (20, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (10, 10, 10), 2)
        cv2.rectangle(self.test_img, (20, 80), (230, 200), (120, 120, 120), 1)

    def test_crc16_integrity(self):
        data = b"0123456789ABCDEF"
        crc1 = crc16_ccitt(data)
        crc2 = crc16_ccitt(data)
        self.assertEqual(crc1, crc2)
        # Verify mutation fails
        self.assertNotEqual(crc1, crc16_ccitt(b"0123456789ABCDEE"))

    def test_hex_bits_roundtrip(self):
        sample_hex = "a1b2c3d4e5f60718"
        bits = hex_to_bits(sample_hex, 64)
        self.assertEqual(len(bits), 64)
        recovered_hex = bits_to_hex(bits)
        self.assertEqual(sample_hex, recovered_hex)

    def test_ecc_packet_roundtrip_clean(self):
        watermark_id = "deadbeefcafebabe"
        packet = encode_payload(watermark_id)
        self.assertEqual(len(packet), PACKET_LENGTH)

        rec_hex, ber, crc_valid = decode_payload(packet)
        self.assertEqual(rec_hex, watermark_id)
        self.assertEqual(ber, 0.0)
        self.assertTrue(crc_valid)

    def test_ecc_packet_majority_vote_correction(self):
        watermark_id = "1234567890abcdef"
        packet = encode_payload(watermark_id)

        # Inject corruptions into copy 1 only (bits 16..95)
        corrupted_packet = packet.copy()
        corrupted_packet[16:30] = 1 - corrupted_packet[16:30]  # flip 14 bits in copy 1

        rec_hex, ber, crc_valid = decode_payload(corrupted_packet)
        self.assertEqual(rec_hex, watermark_id)
        self.assertTrue(crc_valid)
        self.assertGreater(ber, 0.0)  # Majority voting corrected the error

    def test_embed_extract_clean(self):
        watermark_id = "feedface01234567"
        wm_img, packet = embed_watermark(self.test_img, watermark_id, delta=38.0)
        self.assertEqual(wm_img.shape, self.test_img.shape)

        psnr = calculate_psnr(self.test_img, wm_img)
        self.assertGreater(psnr, 35.0, "Watermark must be visually imperceptible (PSNR > 35 dB)")

        extracted_id, ber, crc_valid, meta = extract_watermark(wm_img, search_shifts=False)
        self.assertEqual(extracted_id, watermark_id)
        self.assertEqual(ber, 0.0)
        self.assertTrue(crc_valid)

    def test_watermark_unique_per_session(self):
        id1 = "1111222233334444"
        id2 = "5555666677778888"

        wm1, _ = embed_watermark(self.test_img, id1)
        wm2, _ = embed_watermark(self.test_img, id2)

        # The two watermarked images must be distinct
        self.assertFalse(np.array_equal(wm1, wm2))

        # Each must extract its own ID
        ext1, _, _, _ = extract_watermark(wm1, search_shifts=False)
        ext2, _, _, _ = extract_watermark(wm2, search_shifts=False)
        self.assertEqual(ext1, id1)
        self.assertEqual(ext2, id2)

    def test_jpeg_compression_survival(self):
        watermark_id = "4747474747474747"
        wm_img, _ = embed_watermark(self.test_img, watermark_id, delta=38.0)

        # Compress to JPEG quality 75
        _, enc = cv2.imencode('.jpg', wm_img, [cv2.IMWRITE_JPEG_QUALITY, 75])
        jpg_img = cv2.imdecode(enc, cv2.IMREAD_COLOR)

        extracted_id, ber, crc_valid, _ = extract_watermark(jpg_img, search_shifts=False)
        self.assertEqual(extracted_id, watermark_id)
        self.assertTrue(crc_valid)

    def test_crop_synchronization(self):
        watermark_id = "9876543210fedcba"
        # Use 512x512 canvas for crop testing
        large_canvas = np.ones((512, 512, 3), dtype=np.uint8) * 240
        cv2.putText(large_canvas, "CROP ROBUSTNESS TEST", (40, 100),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (20, 20, 20), 2)

        wm_img, _ = embed_watermark(large_canvas, watermark_id, delta=38.0)

        # 5% crop from top-left (25 pixels vertical, 25 pixels horizontal)
        cropped = wm_img[25:, 25:].copy()

        extracted_id, ber, crc_valid, meta = extract_watermark(cropped, search_shifts=True)
        self.assertEqual(extracted_id, watermark_id)
        self.assertTrue(crc_valid)
        self.assertTrue(meta["aligned"])


if __name__ == "__main__":
    unittest.main()
