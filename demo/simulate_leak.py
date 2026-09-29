"""
Simulated Leak Generator for Demonstration and Evaluation.
SIH Problem Statement 26237.
Simulates real-world exfiltration channels: screenshots, compression, crop, blur, and noise.
"""

import os
import sys
import argparse
import cv2
import numpy as np


def simulate_screenshot(img: np.ndarray) -> np.ndarray:
    """Simulate screen capture: display gamma shift, subtle LCD contrast, and recompression."""
    lut = np.clip((img.astype(np.float32) * 0.98) + 3.0, 0, 255).astype(np.uint8)
    _, enc = cv2.imencode('.jpg', lut, [cv2.IMWRITE_JPEG_QUALITY, 85])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)


def simulate_jpeg(img: np.ndarray, quality: int = 70) -> np.ndarray:
    """Simulate lossy JPEG compression."""
    _, enc = cv2.imencode('.jpg', img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)


def simulate_crop(img: np.ndarray, percent: int = 5) -> np.ndarray:
    """Simulate moderate cropping from edges."""
    h, w = img.shape[:2]
    dy = int(h * (percent / 100.0))
    dx = int(w * (percent / 100.0))
    return img[dy:, dx:].copy()


def simulate_blur(img: np.ndarray) -> np.ndarray:
    """Simulate camera out-of-focus blur."""
    return cv2.GaussianBlur(img, (3, 3), 1.0)


def simulate_noise(img: np.ndarray) -> np.ndarray:
    """Simulate low-light image sensor noise."""
    noise = np.random.normal(0, 4.0, img.shape).astype(np.float32)
    return np.clip(img.astype(np.float32) + noise, 0, 255).astype(np.uint8)


def main():
    parser = argparse.ArgumentParser(description="Simulate leak exfiltration attacks on a document")
    parser.add_argument("--input", "-i", required=True, help="Input watermarked document image path")
    parser.add_argument("--attack", "-a", default="screenshot",
                        choices=["screenshot", "jpeg70", "crop5", "blur", "noise", "all"],
                        help="Attack type to simulate")
    parser.add_argument("--output", "-o", default="demo/leaks/leaked_document.png",
                        help="Output path for leaked document")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}")
        sys.exit(1)

    img = cv2.imread(args.input)
    if img is None:
        print(f"[-] Failed to load image: {args.input}")
        sys.exit(1)

    print(f"[*] Simulating leak attack: '{args.attack}' on {args.input}...")

    if args.attack == "screenshot":
        leaked = simulate_screenshot(img)
    elif args.attack == "jpeg70":
        leaked = simulate_jpeg(img, 70)
    elif args.attack == "crop5":
        leaked = simulate_crop(img, 5)
    elif args.attack == "blur":
        leaked = simulate_blur(img)
    elif args.attack == "noise":
        leaked = simulate_noise(img)
    elif args.attack == "all":
        # Combo: screenshot + crop + blur
        leaked = simulate_blur(simulate_crop(simulate_screenshot(img), 5))

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    cv2.imwrite(args.output, leaked)
    print(f"[+] Leaked document generated: {args.output} (Dimensions: {leaked.shape[1]}x{leaked.shape[0]})")


if __name__ == "__main__":
    main()
