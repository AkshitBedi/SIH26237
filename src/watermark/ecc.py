"""
Forward Error Correction (ECC), Barker Synchronization, and CRC-16 for Watermarking.
Designed for SIH Problem Statement 26237.
"""

import numpy as np
from typing import Tuple, List, Optional

# 16-bit Barker-like synchronization sequence with sharp auto-correlation peak
BARKER_16: List[int] = [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0]
PACKET_LENGTH = 256
DATA_BITS = 64
CRC_BITS = 16


def crc16_ccitt(data_bytes: bytes) -> int:
    """Compute CRC-16 CCITT (0x1021, init 0xFFFF)."""
    crc = 0xFFFF
    for byte in data_bytes:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def hex_to_bits(hex_str: str, num_bits: int = DATA_BITS) -> np.ndarray:
    """Convert a hex string (e.g. 16 hex characters for 64 bits) to a numpy bit array."""
    # Ensure length matches
    raw_bytes = bytes.fromhex(hex_str.rjust(num_bits // 4, '0'))
    bits = []
    for b in raw_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return np.array(bits[:num_bits], dtype=int)


def bits_to_hex(bits: np.ndarray) -> str:
    """Convert a numpy bit array back to a hex string."""
    byte_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]
    res_bytes = bytearray()
    for chunk in byte_chunks:
        val = 0
        for bit in chunk:
            val = (val << 1) | int(bit)
        res_bytes.append(val)
    return res_bytes.hex()


def encode_payload(watermark_id: str) -> np.ndarray:
    """
    Encode a 64-bit watermark ID (16 hex chars) into a 256-bit packet:
    - 16 bits: Barker synchronization preamble
    - 64 bits: watermark ID data payload
    - 16 bits: CRC-16 integrity checksum
    - 160 bits: Rate-3 error-correcting repetition + parity
    Total = 256 bits.
    """
    cleaned_id = watermark_id.strip()
    if len(cleaned_id) < 16:
        cleaned_id = cleaned_id.rjust(16, '0')
    elif len(cleaned_id) > 16:
        cleaned_id = cleaned_id[:16]

    id_bytes = bytes.fromhex(cleaned_id)
    crc_val = crc16_ccitt(id_bytes)

    data_bits = hex_to_bits(cleaned_id, DATA_BITS)
    crc_bits = np.array([(crc_val >> (15 - i)) & 1 for i in range(CRC_BITS)], dtype=int)
    
    # Combined core payload: 80 bits (64 data + 16 crc)
    core = np.concatenate([data_bits, crc_bits])

    # Assemble 256-bit packet:
    # 0..15: Barker preamble (16 bits)
    # 16..95: Core payload copy 1 (80 bits)
    # 96..175: Core payload copy 2 (80 bits)
    # 176..255: Core payload copy 3 (80 bits)
    packet = np.zeros(PACKET_LENGTH, dtype=int)
    packet[:16] = BARKER_16
    packet[16:96] = core
    packet[96:176] = core
    packet[176:256] = core

    return packet


def decode_payload(packet_bits: np.ndarray) -> Tuple[Optional[str], float, bool]:
    """
    Decode a 256-bit packet using majority-vote repetition decoding and CRC-16 check.
    Returns:
        watermark_id (str or None): Decoded 16-hex watermark ID
        ber (float): Estimated bit error rate across the repeated copies
        crc_valid (bool): True if CRC matches
    """
    if len(packet_bits) != PACKET_LENGTH:
        raise ValueError(f"Expected packet length {PACKET_LENGTH}, got {len(packet_bits)}")

    copy1 = packet_bits[16:96]
    copy2 = packet_bits[96:176]
    copy3 = packet_bits[176:256]

    # Majority voting across 3 copies for all 80 bits (64 data + 16 crc)
    votes = copy1 + copy2 + copy3
    majority_core = (votes >= 2).astype(int)

    # Estimate internal BER among copies
    diff1 = np.sum(copy1 != majority_core)
    diff2 = np.sum(copy2 != majority_core)
    diff3 = np.sum(copy3 != majority_core)
    estimated_ber = (diff1 + diff2 + diff3) / (3.0 * 80.0)

    rec_data_bits = majority_core[:64]
    rec_crc_bits = majority_core[64:80]

    rec_hex = bits_to_hex(rec_data_bits)
    rec_bytes = bytes.fromhex(rec_hex)

    rec_crc = 0
    for b in rec_crc_bits:
        rec_crc = (rec_crc << 1) | int(b)

    computed_crc = crc16_ccitt(rec_bytes)
    crc_valid = (rec_crc == computed_crc)

    return rec_hex, float(estimated_ber), crc_valid
