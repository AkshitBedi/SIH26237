# Variant-Segment Encryption (VSE)
## Architectural Roadmap for Eliminating Client-Bypass in Document Watermarking

**Problem Statement**: SIH PS 26237  
**Specification Type**: Production Hardening Specification (Future Roadmap)  
**Status**: Architectural Specification  

---

## 1. The Client-Bypass Problem

In standard client-side watermarking architectures (including the SIH MVP prototype), the decryption workflow proceeds as follows:
```
Encrypted Document + Content Key ──> [ Decrypt Plaintext ] ──> [ Embed Watermark ] ──> Display Document
```

If an adversarial recipient modifies the client binary, attaches a kernel debugger, or dumps memory immediately following the decryption step, they can extract the unwatermarked plaintext document. This renders client-side watermarking vulnerable to skilled insider reverse-engineering.

---

## 2. The Solution: Variant-Segment Encryption (VSE)

Variant-Segment Encryption closes this vulnerability by **moving watermark embedding into the encryption and key release layer**. 

Rather than sending a single encrypted document and relying on the client software to embed a watermark, the document is mathematically structured such that **the recipient cannot decrypt the document without simultaneously reconstructing a watermarked version**.

```
[ Original Document ]
         │
         ▼  (Tile Segmentation)
┌─────────────────────────────────┐
│ Segment 1   Segment 2   ...   N │
└─────────────────────────────────┘
         │
         ▼  (Dual Variant Generation)
For each segment i:
┌───────────────────────────────┐
│ Variant 0 (Bit 0 Modulation)  │ ──> Encrypted with Key K(i, 0)
│ Variant 1 (Bit 1 Modulation)  │ ──> Encrypted with Key K(i, 1)
└───────────────────────────────┘
         │
         ▼  (Ledger Commitment)
Recipient commits Watermark ID: W = [w_1, w_2, ..., w_N] to Ledger
         │
         ▼  (Selective Key Delivery)
Server/KMS releases ONLY keys: { K(1, w_1), K(2, w_2), ..., K(N, w_N) }
         │
         ▼  (Client Decryption)
Client decrypts each tile i using K(i, w_i).
Result: The reconstructed document inherently contains the watermark W!
```

---

## 3. Mathematical & Algorithmic Formulation

### 3.1 Segmentation
The document image or page $D$ with dimensions $H \times W$ is partitioned into an array of $K$ disjoint spatial tiles $\{S_1, S_2, \dots, S_K\}$, where each tile has dimensions $h \times w$ (e.g., $128 \times 128$ pixels).

### 3.2 Dual-Variant Generation
For each segment $S_i$, two visually indistinguishable variants are synthesized:
- $S_{i,0}$: Modulated in the mid-frequency transform domain to encode a binary `0`.
- $S_{i,1}$: Modulated in the mid-frequency transform domain to encode a binary `1`.

The visual difference satisfies:
$$\text{PSNR}(S_{i,0}, S_{i,1}) > 42 \text{ dB}, \quad \text{SSIM}(S_{i,0}, S_{i,1}) > 0.999$$

### 3.3 Symmetric Key Generation & Packaging
For each segment $i \in [1..K]$:
1. Generate two independent 256-bit AES keys: $K_{i,0}$ and $K_{i,1}$.
2. Encrypt $S_{i,0}$ with $K_{i,0} \longrightarrow C_{i,0}$.
3. Encrypt $S_{i,1}$ with $K_{i,1} \longrightarrow C_{i,1}$.

The distribution package contains **both ciphertexts** for every segment:
$$\mathcal{P} = \{ (C_{1,0}, C_{1,1}), (C_{2,0}, C_{2,1}), \dots, (C_{K,0}, C_{K,1}) \}$$

### 3.4 Key Release Protocol
When recipient $R$ authenticates and registers decryption session $S$ on the permissioned ledger, a session watermark payload $W = (w_1, w_2, \dots, w_K) \in \{0, 1\}^K$ is anchored into the block.

Upon 4-of-5 validator consensus, the key distribution service constructs the recipient-specific key bundle:
$$\mathcal{K}_R = \{ K_{i, w_i} \mid i \in [1..K] \}$$

Each key $K_{i, w_i}$ is encapsulated via recipient $R$'s NIST FIPS 203 ML-KEM-768 public key.

---

## 4. Cryptographic Proof of Security

1. **Information-Theoretic Key Seclusion**: For any segment $i$, recipient $R$ receives key $K_{i, w_i}$ and is computationally blinded to the alternate key $K_{i, 1 - w_i}$.
2. **Indistinguishable Decryption**: Because $R$ possesses only key $K_{i, w_i}$, the only plaintext tile $R$ can compute is $S_{i, w_i}$.
3. **No Unwatermarked Assembly**: To assemble an unwatermarked document, an adversary would require $K_{i, 0}$ and $K_{i, 1}$ for all $i$, which are never simultaneously transmitted.
4. **Client-Bypass Impossibility**: Even if the recipient modifies the client binary, bypasses memory protections, or runs custom software, the decrypted data in memory **is already watermarked**.

---

## 5. Prototype vs. Production Comparison

| Attribute | SIH MVP Prototype | Production VSE Architecture |
| :--- | :--- | :--- |
| **Watermark Embedding** | Post-decryption client-side embedding | Pre-encryption dual-variant synthesis |
| **Bypass Prevention** | Software invariant enforcement | Information-theoretic key isolation |
| **Package Overhead** | Single ciphertext + $N$ capsules | $2\times$ tile ciphertext + selective capsules |
| **Client Requirement** | Standard Python client | Standard AES decryptor (no special hooks) |
| **Hardware Reliance** | None | None (Pure Cryptographic Guarantee) |
