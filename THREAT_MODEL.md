# Threat Model & Security Architecture

**Project**: Cryptographic Attribution and Auditable Decryption Provenance for Multi-Recipient Encrypted Document Distribution
**Problem Statement**: SIH PS 26237  
**Classification**: Prototype Security Specification  

---

## 1. Security Philosophy & Terminology

In adherence to scientific rigor and security engineering ethics, this prototype does not employ marketing buzzwords such as *"unhackable"*, *"100% attribution"*, *"military-grade"*, or *"tamper-proof"*. 

Instead, we employ precise, measurable terminology:
- **Tamper-Evident**: Cryptographic mutations in files, blocks, or transactions are deterministically detected.
- **Cryptographically Verifiable**: Digital signatures and Merkle proofs can be independently audited by any party holding the public parameters.
- **Post-Quantum Standardized Algorithms**: Built strictly on NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
- **Measured Watermark Robustness**: Quantitative bit error rates (BER) evaluated under isolated adversarial attacks.
- **Permissioned DLT**: A finite, authorized consortium of validator nodes operating offline.

---

## 2. Protected Assets

| Asset | Description | Security Objective |
| :--- | :--- | :--- |
| **Document Plaintext** | Classified intellectual property or operational directives. | Confidentiality against unauthorized parties and non-recipients. |
| **Decryption Material** | AES-256-GCM symmetric content keys and ML-KEM capsules. | Restricted exclusively to authenticated, intended recipients. |
| **Provenance Ledger** | Hash-linked sequence of signed decryption events. | Tamper evidence, signature verification, and auditability. |
| **Forensic Attribution** | Mathematical mapping between leaked visual artifacts and decrypting recipient. | Accountability and non-deniability. |

---

## 3. Adversary Capabilities & Threat Vectors

### Threat Vector A: Malicious Authorized Recipient (Insider Exfiltration)
- **Profile**: A legitimate recipient (e.g., `REC-047`) possessing valid credentials who attempts to leak classified material to unauthorized channels.
- **Attacker Actions**:
  1. Captures screenshot or photographs screen.
  2. Compresses, crops, resizes, or applies noise/blur to the image to strip forensic markers.
  3. Denies having decrypted or accessed the document.
- **System Defense**:
  - Transform-domain mid-frequency DCT differential modulation survives heavy compression, resizing, and cropping.
  - Recipient’s post-quantum ML-DSA-65 signature on the canonical decryption record provides verifiable signed provenance, assuming the signing key remains under the recipient’s control.

### Threat Vector B: Compromised / Byzantine Validator Node
- **Profile**: 1 of the 5 permissioned validator nodes is rogue, offline, or compromised.
- **Attacker Actions**:
  1. Refuses to sign proposed valid decryption blocks (liveness attack).
  2. Attempts to inject forged records or mutate block history.
- **System Defense**:
  - **4-of-5 Quorum Rule**: Consensus requires $\ge 4$ distinct validator signatures out of 5. A single faulty/Byzantine node cannot halt consensus or commit unauthorized blocks.
  - Previous-hash chaining and Merkle root verification deterministically detect and reject history rewrites.

### Threat Vector C: External Eavesdropper / Network Interceptor
- **Profile**: Passive or active adversary intercepting package distribution.
- **Attacker Actions**:
  1. Intercepts `.pqcpack` multi-recipient distribution file.
  2. Attempts quantum cryptanalysis or classical brute-force.
- **System Defense**:
  - Symmetric payload protected by AES-256-GCM with unique 96-bit nonces.
  - Recipient key capsules protected by NIST FIPS 203 ML-KEM-768 (Module Lattice-based Key Encapsulation Mechanism), offering 128-bit quantum security category matching AES-192/256 equivalent hardness against Shor's and Grover's algorithms.

---

## 4. Trusted Components & Perimeters

1. **Air-Gapped Local Environment**: Keystores and validator ledgers reside on local or isolated local-area networks with zero external internet or cloud KMS dependency.
2. **Local Keystore**: The private key storage on recipient and validator endpoints is assumed protected by OS-level file permissions.
3. **Consensus Quorum**: Security relies on the assumption that **at most 1 out of 5 validators is Byzantine or faulty**. If 2 or more validators collude, the 4-of-5 quorum guarantees cannot hold.

---

## 5. Critical Limitation: The Client-Bypass Gap

> [!WARNING]
> **Honest Prototype Boundary Notice**:
> In the MVP prototype, decryption and watermark embedding are executed on the recipient's endpoint. If an attacker possesses sufficient debugging privileges, reverse-engineers the client binary, or dumps raw memory after the AES content key is unwrapped, they could theoretically extract the plaintext document without executing the watermark embedding subroutine.
>
> This is a known structural limitation of all purely client-side watermarking architectures.

### The Production Solution: Variant-Segment Encryption (VSE)
To completely close the client-bypass gap without requiring trusted hardware (TPM/TEE), the production architecture specifies **Variant-Segment Encryption**:
1. The original document is divided into an array of $M \times N$ tiles.
2. For each tile $i$, two visually indistinguishable variants ($T_{i,0}$ and $T_{i,1}$) are generated with subtle, pre-computed transform-domain differential shifts representing bit `0` and bit `1`.
3. Each variant is encrypted under a unique, independent symmetric key ($K_{i,0}$ and $K_{i,1}$).
4. During distribution, the server/validator **only releases the keys corresponding to the committed watermark bits**:
   $$\{ K_{i, w_i} \mid i \in [1..K] \}$$
5. The recipient **never receives both keys** for any tile. As a result, the only plaintext document the recipient is mathematically capable of decrypting already inherently contains their session watermark.

*(See [docs/variant_segment_encryption.md](file:///c:/Users/akshi/OneDrive/Documents/Desktop/SIH-26237/docs/variant_segment_encryption.md) for full architectural specification).*

---

## 6. Air-Gapped Time Model

In a true air-gapped system, external NTP/GPS time servers are unavailable and local machine clocks may drift or be intentionally manipulated.

**Our Time Architecture**:
1. Individual transaction timestamps represent the local time attested by the decrypting client.
2. The authoritative global sequence of events is governed **strictly by ledger block height**, which provides deterministic event ordering that is tamper-evident under block-hash and validator-signature verification.
3. Validators enforce monotonic block sequence: `block[n].height == block[n-1].height + 1`.
