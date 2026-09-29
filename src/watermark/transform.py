"""
Classical Transform-Domain Invisible Forensic Watermarking.
Implements Block-DCT mid-frequency differential modulation on Luminance (Y) channel
with 16x16 block spatial tiling, Barker synchronization, and majority-voting ECC.
SIH Problem Statement 26237.
"""

import cv2
import numpy as np
from typing import Tuple, Optional, Dict, Any
from src.watermark.ecc import (
    encode_payload,
    decode_payload,
    BARKER_16,
    PACKET_LENGTH,
    DATA_BITS,
    hex_to_bits,
)
from src.watermark.metrics import calculate_ber

# Primary mid-frequency DCT coefficient pair in 8x8 block (row, col)
COEFF_1 = (2, 3)
COEFF_2 = (3, 2)
DEFAULT_DELTA = 38.0
TILE_BLOCKS = 16  # 16x16 blocks per tile = 256 blocks = 256 bits per tile


def embed_watermark(
    image: np.ndarray,
    watermark_id: str,
    delta: float = DEFAULT_DELTA
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Embed a 64-bit watermark ID (16 hex chars) invisibly into an image.

    Args:
        image: BGR image array (H, W, 3)
        watermark_id: 16-hex character string
        delta: Modulation strength (default 38.0 for high robustness and imperceptibility)

    Returns:
        watermarked_image: BGR image array with embedded watermark
        encoded_packet: The 256-bit binary payload packet
    """
    if len(image.shape) == 2:
        img_bgr = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
    else:
        img_bgr = image.copy()

    h, w = img_bgr.shape[:2]
    if h < 128 or w < 128:
        raise ValueError(f"Image dimensions ({w}x{h}) too small; minimum 128x128 required for 16x16 tiling.")

    # Encode payload into 256-bit packet (Barker + data + crc + repetition)
    packet_bits = encode_payload(watermark_id)

    # Convert to YCrCb and extract luminance
    ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)
    y_channel = ycrcb[:, :, 0].astype(np.float32)

    blocks_h = h // 8
    blocks_w = w // 8

    y_mod = y_channel.copy()
    c1_r, c1_c = COEFF_1
    c2_r, c2_c = COEFF_2

    for bi in range(blocks_h):
        for bj in range(blocks_w):
            tile_r = bi % TILE_BLOCKS
            tile_c = bj % TILE_BLOCKS
            bit_idx = tile_r * TILE_BLOCKS + tile_c
            target_bit = packet_bits[bit_idx]

            blk = y_mod[bi * 8:(bi + 1) * 8, bj * 8:(bj + 1) * 8]
            dct_blk = cv2.dct(blk)

            c1 = dct_blk[c1_r, c1_c]
            c2 = dct_blk[c2_r, c2_c]

            if target_bit == 0:
                # Embed 0: c1 - c2 >= delta
                diff = c1 - c2
                if diff < delta:
                    adjust = (delta - diff) / 2.0
                    dct_blk[c1_r, c1_c] += adjust
                    dct_blk[c2_r, c2_c] -= adjust
            else:
                # Embed 1: c2 - c1 >= delta
                diff = c2 - c1
                if diff < delta:
                    adjust = (delta - diff) / 2.0
                    dct_blk[c2_r, c2_c] += adjust
                    dct_blk[c1_r, c1_c] -= adjust

            y_mod[bi * 8:(bi + 1) * 8, bj * 8:(bj + 1) * 8] = cv2.idct(dct_blk)

    # Reassemble watermarked image
    y_clamped = np.clip(y_mod, 0, 255).astype(np.uint8)
    ycrcb[:, :, 0] = y_clamped
    watermarked_bgr = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)

    return watermarked_bgr, packet_bits


def _extract_from_y(
    y_img: np.ndarray,
    shift_y: int = 0,
    shift_x: int = 0,
    block_offset_y: int = 0,
    block_offset_x: int = 0
) -> Tuple[np.ndarray, float]:
    """Internal helper to extract soft scores and Barker correlation at a given grid alignment."""
    sub_y = y_img[shift_y:, shift_x:]
    cur_bh = sub_y.shape[0] // 8
    cur_bw = sub_y.shape[1] // 8

    if cur_bh < 16 or cur_bw < 16:
        return np.zeros(PACKET_LENGTH), 0.0

    c1_r, c1_c = COEFF_1
    c2_r, c2_c = COEFF_2

    soft_scores = np.zeros(PACKET_LENGTH, dtype=np.float32)
    counts = np.zeros(PACKET_LENGTH, dtype=np.int32)

    for bi in range(cur_bh):
        for bj in range(cur_bw):
            tile_r = (bi - block_offset_y) % TILE_BLOCKS
            tile_c = (bj - block_offset_x) % TILE_BLOCKS
            bit_idx = tile_r * TILE_BLOCKS + tile_c

            blk = sub_y[bi * 8:(bi + 1) * 8, bj * 8:(bj + 1) * 8]
            dct_blk = cv2.dct(blk)
            diff = dct_blk[c2_r, c2_c] - dct_blk[c1_r, c1_c]
            soft_scores[bit_idx] += diff
            counts[bit_idx] += 1

    valid_mask = counts > 0
    soft_scores[valid_mask] /= counts[valid_mask]

    # Calculate Barker preamble correlation
    barker_corr = 0.0
    for k in range(16):
        expected = 1.0 if BARKER_16[k] == 1 else -1.0
        barker_corr += expected * soft_scores[k]

    return soft_scores, barker_corr


def extract_watermark(
    image: np.ndarray,
    search_shifts: bool = True
) -> Tuple[Optional[str], float, bool, Dict[str, Any]]:
    """
    Extract and decode a watermark ID from an image.
    Supports shift/crop synchronization via Barker preamble auto-correlation.

    Args:
        image: BGR image array
        search_shifts: If True and zero-shift fails, search sub-pixel and block offsets

    Returns:
        watermark_id (str or None): Extracted 16-hex watermark ID
        ber (float): Estimated bit error rate
        crc_valid (bool): True if CRC verification succeeded
        metadata (dict): Extraction statistics (Barker correlation, alignment offsets, etc.)
    """
    if len(image.shape) == 2:
        img_bgr = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
    else:
        img_bgr = image.copy()

    ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)
    y_channel = ycrcb[:, :, 0].astype(np.float32)

    # 1. Try zero-shift alignment first (fast path)
    scores, corr = _extract_from_y(y_channel, 0, 0, 0, 0)
    packet_bits = (scores > 0).astype(int)
    rec_hex, ber, crc_valid = decode_payload(packet_bits)

    if crc_valid:
        return rec_hex, ber, True, {
            "barker_correlation": float(corr),
            "pixel_shift": (0, 0),
            "block_offset": (0, 0),
            "aligned": True
        }

    if not search_shifts:
        return rec_hex, ber, crc_valid, {
            "barker_correlation": float(corr),
            "pixel_shift": (0, 0),
            "block_offset": (0, 0),
            "aligned": False
        }

    # 2. Search pixel shifts (0..7) and block offsets (0..15)
    best_corr = corr
    best_res = (rec_hex, ber, crc_valid)
    best_alignment = (0, 0, 0, 0)

    for py in range(8):
        for px in range(8):
            sub_y = y_channel[py:, px:]
            cur_bh = sub_y.shape[0] // 8
            cur_bw = sub_y.shape[1] // 8
            if cur_bh < 16 or cur_bw < 16:
                continue

            # Compute DCT differences once for this pixel shift
            c1_r, c1_c = COEFF_1
            c2_r, c2_c = COEFF_2
            diff_grid = np.zeros((cur_bh, cur_bw), dtype=np.float32)
            for bi in range(cur_bh):
                for bj in range(cur_bw):
                    blk = sub_y[bi * 8:(bi + 1) * 8, bj * 8:(bj + 1) * 8]
                    d = cv2.dct(blk)
                    diff_grid[bi, bj] = d[c2_r, c2_c] - d[c1_r, c1_c]

            # Test tile block offsets (by, bx)
            for by in range(TILE_BLOCKS):
                for bx in range(TILE_BLOCKS):
                    cur_corr = 0.0
                    for k in range(16):
                        expected = 1.0 if BARKER_16[k] == 1 else -1.0
                        tile_r = k // TILE_BLOCKS
                        tile_c = k % TILE_BLOCKS
                        val_sum = 0.0
                        val_cnt = 0
                        for ti in range((cur_bh - by) // TILE_BLOCKS):
                            for tj in range((cur_bw - bx) // TILE_BLOCKS):
                                val_sum += diff_grid[by + ti * TILE_BLOCKS + tile_r, bx + tj * TILE_BLOCKS + tile_c]
                                val_cnt += 1
                        if val_cnt > 0:
                            cur_corr += expected * (val_sum / val_cnt)

                    if cur_corr > best_corr:
                        # Full extraction at this promising alignment
                        soft_sc = np.zeros(PACKET_LENGTH, dtype=np.float32)
                        cnts = np.zeros(PACKET_LENGTH, dtype=np.int32)
                        for bi in range(cur_bh):
                            for bj in range(cur_bw):
                                tr = (bi - by) % TILE_BLOCKS
                                tc = (bj - bx) % TILE_BLOCKS
                                b_idx = tr * TILE_BLOCKS + tc
                                soft_sc[b_idx] += diff_grid[bi, bj]
                                cnts[b_idx] += 1
                        valid = cnts > 0
                        soft_sc[valid] /= cnts[valid]
                        cand_bits = (soft_sc > 0).astype(int)
                        cand_hex, cand_ber, cand_crc = decode_payload(cand_bits)

                        best_corr = cur_corr
                        best_res = (cand_hex, cand_ber, cand_crc)
                        best_alignment = (py, px, by, bx)

                        if cand_crc:
                            return cand_hex, cand_ber, True, {
                                "barker_correlation": float(best_corr),
                                "pixel_shift": (py, px),
                                "block_offset": (by, bx),
                                "aligned": True
                            }

    return best_res[0], best_res[1], best_res[2], {
        "barker_correlation": float(best_corr),
        "pixel_shift": (best_alignment[0], best_alignment[1]),
        "block_offset": (best_alignment[2], best_alignment[3]),
        "aligned": best_res[2]
    }
