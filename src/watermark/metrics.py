"""
Watermark Quality and Robustness Metrics: BER, PSNR, SSIM.
SIH Problem Statement 26237.
"""

import cv2
import numpy as np


def calculate_ber(original_bits: np.ndarray, extracted_bits: np.ndarray) -> float:
    """Calculate exact Bit Error Rate (BER) between original and extracted bit sequences."""
    if len(original_bits) != len(extracted_bits):
        min_len = min(len(original_bits), len(extracted_bits))
        original_bits = original_bits[:min_len]
        extracted_bits = extracted_bits[:min_len]
    if len(original_bits) == 0:
        return 0.0
    errors = np.sum(np.array(original_bits) != np.array(extracted_bits))
    return float(errors) / float(len(original_bits))


def calculate_psnr(img1: np.ndarray, img2: np.ndarray) -> float:
    """Compute Peak Signal-to-Noise Ratio (PSNR) in dB."""
    if img1.shape != img2.shape:
        img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))
    return float(cv2.PSNR(img1, img2))


def calculate_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """
    Compute Mean Structural Similarity Index (SSIM) on luminance channel.
    Values range from -1 to 1; 1 indicates identical images.
    """
    if img1.shape != img2.shape:
        img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

    if len(img1.shape) == 3:
        y1 = cv2.cvtColor(img1, cv2.COLOR_BGR2YCrCb)[:, :, 0].astype(np.float64)
        y2 = cv2.cvtColor(img2, cv2.COLOR_BGR2YCrCb)[:, :, 0].astype(np.float64)
    else:
        y1 = img1.astype(np.float64)
        y2 = img2.astype(np.float64)

    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2

    kernel = cv2.getGaussianKernel(11, 1.5)
    window = np.outer(kernel, kernel.transpose())

    mu1 = cv2.filter2D(y1, -1, window)[5:-5, 5:-5]
    mu2 = cv2.filter2D(y2, -1, window)[5:-5, 5:-5]

    mu1_sq = mu1 ** 2
    mu2_sq = mu2 ** 2
    mu1_mu2 = mu1 * mu2

    sigma1_sq = cv2.filter2D(y1 ** 2, -1, window)[5:-5, 5:-5] - mu1_sq
    sigma2_sq = cv2.filter2D(y2 ** 2, -1, window)[5:-5, 5:-5] - mu2_sq
    sigma12 = cv2.filter2D(y1 * y2, -1, window)[5:-5, 5:-5] - mu1_mu2

    ssim_map = ((2 * mu1_mu2 + c1) * (2 * sigma12 + c2)) / ((mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2))
    return float(np.mean(ssim_map))
