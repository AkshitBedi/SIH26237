"""
Unit and Security Tests for Post-Quantum Cryptography and Identity Modules.
SIH Problem Statement 26237.
"""

import os
import shutil
import tempfile
import unittest
from src.crypto.canonical import canonicalize, canonical_json_str
from src.crypto.symmetric import (
    sha3_256,
    sha3_256_bytes,
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from src.crypto.pqc import (
    generate_mlkem_keypair,
    mlkem_encapsulate,
    mlkem_decapsulate,
    serialize_mlkem_public_key,
    deserialize_mlkem_public_key,
    serialize_mlkem_private_key,
    deserialize_mlkem_private_key,
    generate_mldsa_keypair,
    mldsa_sign,
    mldsa_verify,
    serialize_mldsa_public_key,
    deserialize_mldsa_public_key,
    serialize_mldsa_private_key,
    deserialize_mldsa_private_key,
)
from src.identity.keystore import LocalKeystore
from src.identity.auth import create_auth_challenge, respond_to_challenge, verify_auth_response
from cryptography.exceptions import InvalidTag


class TestCryptoAndIdentity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore = LocalKeystore(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- Canonicalization Tests ---
    def test_canonicalize_order_invariance(self):
        d1 = {"z": 1, "a": {"k2": "val2", "k1": "val1"}}
        d2 = {"a": {"k1": "val1", "k2": "val2"}, "z": 1}
        self.assertEqual(canonicalize(d1), canonicalize(d2))
        self.assertEqual(canonical_json_str(d1), '{"a":{"k1":"val1","k2":"val2"},"z":1}')

    # --- Symmetric Crypto Tests ---
    def test_sha3_256_hash(self):
        data = b"Post-Quantum Provenance SIH 26237"
        h1 = sha3_256(data)
        h2 = sha3_256(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        self.assertNotEqual(h1, sha3_256(data + b"!"))

    def test_aes_gcm_roundtrip(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Classified Defence Telemetry Payload 2026"
        aad = b"header_metadata"

        ct, n, tag = encrypt_aes_gcm(plaintext, key, nonce, aad)
        self.assertEqual(n, nonce)
        self.assertEqual(len(tag), 16)

        recovered = decrypt_aes_gcm(ct, key, n, tag, aad)
        self.assertEqual(recovered, plaintext)

    def test_aes_gcm_tamper_rejection(self):
        key = generate_aes_key()
        plaintext = b"Authentic Data"
        ct, nonce, tag = encrypt_aes_gcm(plaintext, key)

        # Tampered ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(bytes(tampered_ct), key, nonce, tag)

        # Tampered tag
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(ct, key, nonce, bytes(tampered_tag))

    # --- ML-KEM-768 Tests ---
    def test_mlkem768_encapsulate_decapsulate(self):
        priv, pub = generate_mlkem_keypair()
        shared_secret, ciphertext = mlkem_encapsulate(pub)

        self.assertEqual(len(shared_secret), 32)
        self.assertEqual(len(ciphertext), 1088)

        recovered_secret = mlkem_decapsulate(priv, ciphertext)
        self.assertEqual(shared_secret, recovered_secret)

    def test_mlkem768_wrong_key_implicit_rejection(self):
        _, pub = generate_mlkem_keypair()
        wrong_priv, _ = generate_mlkem_keypair()

        shared_secret, ciphertext = mlkem_encapsulate(pub)
        recovered_wrong = mlkem_decapsulate(wrong_priv, ciphertext)
        # In ML-KEM, decapsulating with wrong key returns a pseudorandom distinct secret
        self.assertNotEqual(shared_secret, recovered_wrong)

    def test_mlkem_serialization(self):
        priv, pub = generate_mlkem_keypair()
        pub_pem = serialize_mlkem_public_key(pub)
        priv_pem = serialize_mlkem_private_key(priv)

        loaded_pub = deserialize_mlkem_public_key(pub_pem)
        loaded_priv = deserialize_mlkem_private_key(priv_pem)

        ss, ct = mlkem_encapsulate(loaded_pub)
        ss_rec = mlkem_decapsulate(loaded_priv, ct)
        self.assertEqual(ss, ss_rec)

    # --- ML-DSA-65 Tests ---
    def test_mldsa65_sign_verify(self):
        priv, pub = generate_mldsa_keypair()
        message = b"Immutable Decryption Record #047"
        sig = mldsa_sign(priv, message)

        self.assertEqual(len(sig), 3309)
        self.assertTrue(mldsa_verify(pub, sig, message))

    def test_mldsa65_tampered_message_rejection(self):
        priv, pub = generate_mldsa_keypair()
        message = b"Authorized Decryption"
        sig = mldsa_sign(priv, message)

        self.assertFalse(mldsa_verify(pub, sig, b"Unauthorized Decryption"))

    def test_mldsa65_tampered_signature_rejection(self):
        priv, pub = generate_mldsa_keypair()
        message = b"Immutable Record"
        sig = mldsa_sign(priv, message)

        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0x55
        self.assertFalse(mldsa_verify(pub, bytes(tampered_sig), message))

    def test_mldsa_serialization(self):
        priv, pub = generate_mldsa_keypair()
        pub_pem = serialize_mldsa_public_key(pub)
        priv_pem = serialize_mldsa_private_key(priv)

        loaded_pub = deserialize_mldsa_public_key(pub_pem)
        loaded_priv = deserialize_mldsa_private_key(priv_pem)

        sig = mldsa_sign(loaded_priv, b"Signed Payload")
        self.assertTrue(mldsa_verify(loaded_pub, sig, b"Signed Payload"))

    # --- Keystore & Authentication Tests ---
    def test_keystore_demo_setup(self):
        registry = self.keystore.setup_demo_identities()
        self.assertIn("REC-001", registry["recipients"])
        self.assertIn("REC-002", registry["recipients"])
        self.assertIn("REC-047", registry["recipients"])
        self.assertEqual(len(registry["validators"]), 5)
        self.assertIn("SENDER-HQ", registry["senders"])

        # Check retrieval
        rec_pub_kem = self.keystore.get_recipient_kem_public_key("REC-047")
        rec_priv_kem = self.keystore.get_recipient_kem_private_key("REC-047")
        ss, ct = mlkem_encapsulate(rec_pub_kem)
        self.assertEqual(ss, mlkem_decapsulate(rec_priv_kem, ct))

    def test_challenge_response_authentication(self):
        self.keystore.setup_demo_identities()
        challenge = create_auth_challenge("REC-047", self.keystore)
        response = respond_to_challenge(challenge, self.keystore)

        valid, reason = verify_auth_response(response, self.keystore)
        self.assertTrue(valid, f"Auth failed: {reason}")

    def test_challenge_response_forged_signature_rejection(self):
        self.keystore.setup_demo_identities()
        challenge = create_auth_challenge("REC-047", self.keystore)

        # Attacker with a different keypair signs
        attacker_priv, _ = generate_mldsa_keypair()
        forged_sig = mldsa_sign(attacker_priv, canonicalize(challenge))
        import base64
        forged_response = {
            "challenge": challenge,
            "recipient_id": "REC-047",
            "signature": base64.b64encode(forged_sig).decode('utf-8')
        }

        valid, reason = verify_auth_response(forged_response, self.keystore)
        self.assertFalse(valid)
        self.assertIn("Invalid ML-DSA-65 signature", reason)


if __name__ == "__main__":
    unittest.main()
