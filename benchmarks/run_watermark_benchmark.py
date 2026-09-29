"""
Watermark Robustness Benchmark Tool.
Built for SIH Problem Statement 26237.
Tests transform-domain watermark survival against real-world degradation attacks.
Generates machine-readable (JSON) and human-readable benchmark reports.
"""

import os
import sys
import json
import time
import secrets
import cv2
import numpy as np

# Ensure root directory is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.watermark.transform import embed_watermark, extract_watermark
from src.watermark.metrics import calculate_ber, calculate_psnr, calculate_ssim
from src.watermark.ecc import hex_to_bits


def create_realistic_document(width: int = 1024, height: int = 1024) -> np.ndarray:
    """Generate a realistic official classified document canvas."""
    img = np.ones((height, width, 3), dtype=np.uint8) * 248  # Off-white paper background

    # Subtle paper texture / light grain
    noise = np.random.normal(0, 1.5, (height, width, 3))
    img = np.clip(img.astype(np.float32) + noise, 0, 255).astype(np.uint8)

    # Top & Bottom Classification Banners (Red)
    cv2.rectangle(img, (0, 0), (width, 50), (30, 30, 180), -1)
    cv2.rectangle(img, (0, height - 50), (width, height), (30, 30, 180), -1)
    cv2.putText(img, "TOP SECRET // SIH-26237 // ORCON // PQC RESTRICTED",
                (120, 35), cv2.FONT_HERSHEY_DUPLEX, 0.85, (255, 255, 255), 2)
    cv2.putText(img, "UNAUTHORIZED DISCLOSURE SUBJECT TO LEGAL PROSECUTION",
                (100, height - 20), cv2.FONT_HERSHEY_DUPLEX, 0.7, (255, 255, 255), 1)

    # Header Emblem
    center_x = width // 2
    cv2.circle(img, (center_x, 115), 45, (80, 80, 80), 2)
    cv2.circle(img, (center_x, 115), 35, (120, 120, 120), 1)
    cv2.putText(img, "GOVT OF INDIA", (center_x - 55, 120),
                cv2.FONT_HERSHEY_SIMPLEX, 0.45, (60, 60, 60), 1)

    # Document Header
    cv2.putText(img, "DEPARTMENT OF DEFENCE RESEARCH & DEVELOPMENT",
                (center_x - 300, 190), cv2.FONT_HERSHEY_SIMPLEX, 0.75, (20, 20, 20), 2)
    cv2.putText(img, "SECURE MULTI-RECIPIENT CRYPTOGRAPHIC DISPATCH",
                (center_x - 275, 225), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (50, 50, 50), 2)

    # Metadata Box
    cv2.rectangle(img, (60, 250), (width - 60, 340), (160, 160, 160), 1)
    cv2.putText(img, "DISPATCH ID: MOD-2026-PQC-0982", (80, 280),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (40, 40, 40), 1)
    cv2.putText(img, "DATE: 2026-09-29 | TIME-SOURCE: LOCAL LEDGER ATTESTED", (80, 305),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (40, 40, 40), 1)
    cv2.putText(img, "ENCRYPTION: NIST FIPS 203 ML-KEM-768 | AES-256-GCM", (80, 330),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (40, 40, 40), 1)

    # Body Paragraphs / Lines
    body_y = 390
    paragraphs = [
        "1. MEMORANDUM FOR AUTHORIZED RECIPIENTS (REC-001, REC-002, REC-047).",
        "2. This document contains sensitive cryptographic operational provenance standards.",
        "3. Decryption events are irrevocably signed with recipient ML-DSA-65 keys and anchored",
        "   into the offline permissioned ledger by 4-of-5 validator consensus prior to release.",
        "4. Forensic attribution markers are invisibly modulated into the transform domain.",
        "5. Any unauthorized exfiltration, screenshot, photograph, or duplicate will be attributed",
        "   directly to the decrypting session and recipient identity via ledger verification."
    ]

    for p in paragraphs:
        cv2.putText(img, p, (70, body_y), cv2.FONT_HERSHEY_SIMPLEX, 0.58, (25, 25, 25), 1)
        body_y += 35

    # Simulated Data Table
    table_y = body_y + 30
    cv2.rectangle(img, (70, table_y), (width - 70, table_y + 160), (140, 140, 140), 2)
    cv2.line(img, (70, table_y + 40), (width - 70, table_y + 40), (140, 140, 140), 1)
    cv2.line(img, (260, table_y), (260, table_y + 160), (140, 140, 140), 1)
    cv2.line(img, (580, table_y), (580, table_y + 160), (140, 140, 140), 1)

    cv2.putText(img, "NODE IDENTIFIER", (90, table_y + 28), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (10, 10, 10), 2)
    cv2.putText(img, "ROLE / AUTHORITY", (280, table_y + 28), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (10, 10, 10), 2)
    cv2.putText(img, "PQC SIGNATURE STATUS", (600, table_y + 28), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (10, 10, 10), 2)

    rows = [
        ("VAL-01 .. VAL-05", "Permissioned Byzantine Validators", "ML-DSA-65 4/5 Quorum Active"),
        ("REC-047", "Authorized Air-Gap Recipient", "Registered in Local Keystore"),
        ("PROVENANCE-D1", "Document Decryption Engine", "Commit-Before-Release Active"),
    ]
    for idx, (c1, c2, c3) in enumerate(rows):
        ry = table_y + 75 + idx * 35
        cv2.putText(img, c1, (90, ry), cv2.FONT_HERSHEY_SIMPLEX, 0.50, (40, 40, 40), 1)
        cv2.putText(img, c2, (280, ry), cv2.FONT_HERSHEY_SIMPLEX, 0.50, (40, 40, 40), 1)
        cv2.putText(img, c3, (600, ry), cv2.FONT_HERSHEY_SIMPLEX, 0.50, (40, 40, 40), 1)

    # Security Stamp / Seal
    cv2.circle(img, (width - 180, height - 160), 65, (40, 40, 180), 3)
    cv2.putText(img, "OFFICIAL", (width - 235, height - 165), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (40, 40, 180), 2)
    cv2.putText(img, "VALIDATED", (width - 245, height - 140), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (40, 40, 180), 2)

    return img


def apply_attack(img: np.ndarray, attack_name: str) -> np.ndarray:
    """Apply an isolated real-world degradation attack to a watermarked image."""
    h, w = img.shape[:2]

    if attack_name == "Baseline (No Attack)":
        return img.copy()

    elif attack_name.startswith("JPEG Q"):
        q = int(attack_name.split("Q")[1])
        _, enc = cv2.imencode('.jpg', img, [cv2.IMWRITE_JPEG_QUALITY, q])
        return cv2.imdecode(enc, cv2.IMREAD_COLOR)

    elif attack_name.startswith("Resize "):
        pct = int(attack_name.split(" ")[1].replace("%", ""))
        scale = pct / 100.0
        down = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        return cv2.resize(down, (w, h), interpolation=cv2.INTER_LINEAR)

    elif attack_name.startswith("Crop "):
        pct = int(attack_name.split(" ")[1].replace("%", ""))
        offset_y = int(h * (pct / 100.0))
        offset_x = int(w * (pct / 100.0))
        # Crop from top-left, leaving bottom-right
        return img[offset_y:, offset_x:].copy()

    elif attack_name == "Gaussian Blur (3x3)":
        return cv2.GaussianBlur(img, (3, 3), 1.0)

    elif attack_name == "Gaussian Noise (sigma=4)":
        noise = np.random.normal(0, 4.0, img.shape).astype(np.float32)
        return np.clip(img.astype(np.float32) + noise, 0, 255).astype(np.uint8)

    elif attack_name == "Screenshot / Display Re-encode":
        # Simulate LCD capture / screenshot: subtle brightness boost, contrast compression, and JPEG recompression
        lut = np.clip((img.astype(np.float32) * 0.97) + 4.0, 0, 255).astype(np.uint8)
        _, enc = cv2.imencode('.jpg', lut, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return cv2.imdecode(enc, cv2.IMREAD_COLOR)

    elif attack_name == "Print-Cam Simulation":
        # Perspective tilt + lighting gradient + re-encoding
        pts1 = np.float32([[0, 0], [w, 0], [0, h], [w, h]])
        pts2 = np.float32([[8, 12], [w - 10, 5], [12, h - 8], [w - 5, h - 15]])
        matrix = cv2.getPerspectiveTransform(pts1, pts2)
        warped = cv2.warpPerspective(img, matrix, (w, h), borderMode=cv2.BORDER_REPLICATE)
        _, enc = cv2.imencode('.jpg', warped, [cv2.IMWRITE_JPEG_QUALITY, 80])
        return cv2.imdecode(enc, cv2.IMREAD_COLOR)

    else:
        raise ValueError(f"Unknown attack: {attack_name}")


def run_benchmark(output_dir: str = "benchmarks") -> dict:
    """Run full watermark benchmark and generate reports."""
    os.makedirs(output_dir, exist_ok=True)

    print("================================================================================")
    print("  SIH PROBLEM STATEMENT 26237: FORENSIC WATERMARK ROBUSTNESS BENCHMARK")
    print("================================================================================")
    print("[*] Generating realistic 1024x1024 classified document canvas...")
    original_img = create_realistic_document(1024, 1024)

    # Save original document sample
    sample_doc_path = os.path.join(output_dir, "sample_document.png")
    cv2.imwrite(sample_doc_path, original_img)

    # Generate random 64-bit watermark ID (16 hex chars)
    watermark_id = secrets.token_hex(8)
    original_bits = hex_to_bits(watermark_id, 64)
    print(f"[*] Generated Target Watermark ID: 0x{watermark_id.upper()} (64 bits)")

    # Embed watermark
    t0 = time.time()
    watermarked_img, _ = embed_watermark(original_img, watermark_id, delta=38.0)
    embed_ms = (time.time() - t0) * 1000.0

    wm_path = os.path.join(output_dir, "watermarked_document.png")
    cv2.imwrite(wm_path, watermarked_img)

    # Compute fidelity metrics
    psnr = calculate_psnr(original_img, watermarked_img)
    ssim = calculate_ssim(original_img, watermarked_img)
    print(f"[*] Watermark Embedded in {embed_ms:.2f} ms")
    print(f"[*] Visual Quality: PSNR = {psnr:.2f} dB | SSIM = {ssim:.4f} (Imperceptible)")
    print("--------------------------------------------------------------------------------")

    attacks = [
        "Baseline (No Attack)",
        "JPEG Q90",
        "JPEG Q80",
        "JPEG Q70",
        "JPEG Q50",
        "Resize 75%",
        "Resize 50%",
        "Crop 5%",
        "Crop 10%",
        "Gaussian Blur (3x3)",
        "Gaussian Noise (sigma=4)",
        "Screenshot / Display Re-encode",
        "Print-Cam Simulation",
    ]

    results = []

    print(f"{'Attack / Transformation':<32} {'BER':<10} {'PSNR (dB)':<12} {'Decoded':<10} {'CRC':<8} {'Time (ms)'}")
    print("-" * 80)

    for attack in attacks:
        attacked = apply_attack(watermarked_img, attack)

        t_start = time.time()
        extracted_id, est_ber, crc_valid, meta = extract_watermark(attacked, search_shifts=True)
        dur_ms = (time.time() - t_start) * 1000.0

        if extracted_id is not None:
            extracted_bits = hex_to_bits(extracted_id, 64)
            measured_ber = calculate_ber(original_bits, extracted_bits)
            is_match = (extracted_id.lower() == watermark_id.lower())
        else:
            measured_ber = 1.0
            is_match = False

        decoded_str = "YES" if is_match else "NO"
        crc_str = "VALID" if crc_valid else "FAIL"

        # Calculate PSNR against watermarked if dimensions match
        if attacked.shape == watermarked_img.shape:
            att_psnr = calculate_psnr(watermarked_img, attacked)
            psnr_str = f"{att_psnr:.2f}"
        else:
            psnr_str = "N/A (Crop)"

        print(f"{attack:<32} {measured_ber * 100.0:>5.1f}%    {psnr_str:<12} {decoded_str:<10} {crc_str:<8} {dur_ms:>7.1f}")

        results.append({
            "attack": attack,
            "measured_ber": float(measured_ber),
            "ber_percentage": f"{measured_ber * 100.0:.2f}%",
            "decoded": is_match,
            "crc_valid": crc_valid,
            "extracted_id": extracted_id,
            "duration_ms": round(dur_ms, 2),
            "attack_psnr": psnr_str,
            "metadata": meta
        })

    print("================================================================================")

    # Produce machine-readable report
    benchmark_report = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "watermark_id": watermark_id,
        "payload_bits": 64,
        "fidelity": {
            "psnr_db": round(psnr, 2),
            "ssim": round(ssim, 4),
            "embedding_time_ms": round(embed_ms, 2)
        },
        "tests_total": len(attacks),
        "tests_passed": sum(1 for r in results if r["decoded"]),
        "results": results
    }

    report_path = os.path.join(output_dir, "benchmark_results.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_report, f, indent=2)

    print(f"[+] Machine-readable benchmark report saved to: {report_path}")
    print(f"[+] Overall Success Rate: {benchmark_report['tests_passed']}/{benchmark_report['tests_total']} attacks survived.")
    return benchmark_report


if __name__ == "__main__":
    run_benchmark()
