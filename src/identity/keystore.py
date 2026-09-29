"""
Local Keystore and Identity Management for Air-Gapped Deployments.
Manages NIST PQC keypairs (ML-KEM-768 and ML-DSA-65) for Recipients and Validators.
SIH Problem Statement 26237.
"""

import os
import json
from typing import Dict, Any, Optional, List
from src.crypto.pqc import (
    generate_mlkem_keypair,
    generate_mldsa_keypair,
    serialize_mlkem_public_key,
    deserialize_mlkem_public_key,
    serialize_mlkem_private_key,
    deserialize_mlkem_private_key,
    serialize_mldsa_public_key,
    deserialize_mldsa_public_key,
    serialize_mldsa_private_key,
    deserialize_mldsa_private_key,
)
from src.crypto.symmetric import sha3_256


class LocalKeystore:
    """Offline local keystore for recipients and permissioned ledger validators."""

    def __init__(self, base_dir: str = "data/keystore"):
        self.base_dir = os.path.abspath(base_dir)
        self.public_dir = os.path.join(self.base_dir, "public")
        self.private_dir = os.path.join(self.base_dir, "private")
        self.registry_file = os.path.join(self.base_dir, "public_registry.json")

        os.makedirs(self.public_dir, exist_ok=True)
        os.makedirs(self.private_dir, exist_ok=True)

    def _load_registry(self) -> Dict[str, Any]:
        if os.path.exists(self.registry_file):
            with open(self.registry_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"recipients": {}, "validators": {}, "senders": {}}

    def _save_registry(self, registry: Dict[str, Any]) -> None:
        with open(self.registry_file, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)

    def register_recipient(self, recipient_id: str) -> Dict[str, Any]:
        """Generate and store ML-KEM-768 and ML-DSA-65 keypairs for a recipient."""
        # ML-KEM for key decapsulation
        kem_priv, kem_pub = generate_mlkem_keypair()
        kem_pub_pem = serialize_mlkem_public_key(kem_pub)
        kem_priv_pem = serialize_mlkem_private_key(kem_priv)

        # ML-DSA for identity challenge-response & decryption signing
        dsa_priv, dsa_pub = generate_mldsa_keypair()
        dsa_pub_pem = serialize_mldsa_public_key(dsa_pub)
        dsa_priv_pem = serialize_mldsa_private_key(dsa_priv)

        # Public fingerprint
        dsa_pub_fingerprint = sha3_256(dsa_pub_pem.encode('utf-8'))[:16]

        # Save private material
        priv_path = os.path.join(self.private_dir, f"{recipient_id}.priv.json")
        with open(priv_path, "w", encoding="utf-8") as f:
            json.dump({
                "recipient_id": recipient_id,
                "mlkem_private_key_pem": kem_priv_pem,
                "mldsa_private_key_pem": dsa_priv_pem
            }, f, indent=2)

        # Update public registry
        registry = self._load_registry()
        registry["recipients"][recipient_id] = {
            "recipient_id": recipient_id,
            "mlkem_public_key_pem": kem_pub_pem,
            "mldsa_public_key_pem": dsa_pub_pem,
            "dsa_fingerprint": dsa_pub_fingerprint
        }
        self._save_registry(registry)
        return registry["recipients"][recipient_id]

    def register_validator(self, validator_id: str) -> Dict[str, Any]:
        """Generate and store ML-DSA-65 keypair for a ledger validator."""
        dsa_priv, dsa_pub = generate_mldsa_keypair()
        dsa_pub_pem = serialize_mldsa_public_key(dsa_pub)
        dsa_priv_pem = serialize_mldsa_private_key(dsa_priv)

        dsa_pub_fingerprint = sha3_256(dsa_pub_pem.encode('utf-8'))[:16]

        # Save private material
        priv_path = os.path.join(self.private_dir, f"{validator_id}.priv.json")
        with open(priv_path, "w", encoding="utf-8") as f:
            json.dump({
                "validator_id": validator_id,
                "mldsa_private_key_pem": dsa_priv_pem
            }, f, indent=2)

        # Update public registry
        registry = self._load_registry()
        registry["validators"][validator_id] = {
            "validator_id": validator_id,
            "mldsa_public_key_pem": dsa_pub_pem,
            "dsa_fingerprint": dsa_pub_fingerprint
        }
        self._save_registry(registry)
        return registry["validators"][validator_id]

    def register_sender(self, sender_id: str) -> Dict[str, Any]:
        """Generate and store ML-DSA-65 keypair for a dispatch sender."""
        dsa_priv, dsa_pub = generate_mldsa_keypair()
        dsa_pub_pem = serialize_mldsa_public_key(dsa_pub)
        dsa_priv_pem = serialize_mldsa_private_key(dsa_priv)
        dsa_pub_fingerprint = sha3_256(dsa_pub_pem.encode('utf-8'))[:16]

        priv_path = os.path.join(self.private_dir, f"{sender_id}.priv.json")
        with open(priv_path, "w", encoding="utf-8") as f:
            json.dump({
                "sender_id": sender_id,
                "mldsa_private_key_pem": dsa_priv_pem
            }, f, indent=2)

        registry = self._load_registry()
        registry["senders"][sender_id] = {
            "sender_id": sender_id,
            "mldsa_public_key_pem": dsa_pub_pem,
            "dsa_fingerprint": dsa_pub_fingerprint
        }
        self._save_registry(registry)
        return registry["senders"][sender_id]

    # Key Retrieval Helpers
    def get_recipient_kem_public_key(self, recipient_id: str):
        reg = self._load_registry()
        if recipient_id not in reg["recipients"]:
            raise KeyError(f"Recipient {recipient_id} not registered.")
        return deserialize_mlkem_public_key(reg["recipients"][recipient_id]["mlkem_public_key_pem"])

    def get_recipient_kem_private_key(self, recipient_id: str):
        path = os.path.join(self.private_dir, f"{recipient_id}.priv.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key for {recipient_id} not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return deserialize_mlkem_private_key(data["mlkem_private_key_pem"])

    def get_recipient_dsa_public_key(self, recipient_id: str):
        reg = self._load_registry()
        if recipient_id not in reg["recipients"]:
            raise KeyError(f"Recipient {recipient_id} not registered.")
        return deserialize_mldsa_public_key(reg["recipients"][recipient_id]["mldsa_public_key_pem"])

    def get_recipient_dsa_private_key(self, recipient_id: str):
        path = os.path.join(self.private_dir, f"{recipient_id}.priv.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key for {recipient_id} not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return deserialize_mldsa_private_key(data["mldsa_private_key_pem"])

    def get_validator_dsa_public_key(self, validator_id: str):
        reg = self._load_registry()
        if validator_id not in reg["validators"]:
            raise KeyError(f"Validator {validator_id} not registered.")
        return deserialize_mldsa_public_key(reg["validators"][validator_id]["mldsa_public_key_pem"])

    def get_validator_dsa_private_key(self, validator_id: str):
        path = os.path.join(self.private_dir, f"{validator_id}.priv.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key for {validator_id} not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return deserialize_mldsa_private_key(data["mldsa_private_key_pem"])

    def get_sender_dsa_public_key(self, sender_id: str):
        reg = self._load_registry()
        if sender_id not in reg["senders"]:
            raise KeyError(f"Sender {sender_id} not registered.")
        return deserialize_mldsa_public_key(reg["senders"][sender_id]["mldsa_public_key_pem"])

    def get_sender_dsa_private_key(self, sender_id: str):
        path = os.path.join(self.private_dir, f"{sender_id}.priv.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key for {sender_id} not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return deserialize_mldsa_private_key(data["mldsa_private_key_pem"])

    def get_public_registry(self) -> Dict[str, Any]:
        return self._load_registry()

    def setup_demo_identities(self) -> Dict[str, Any]:
        """Convenience method to populate demo identities: 3 recipients, 5 validators, 1 sender."""
        recipients = ["REC-001", "REC-002", "REC-047"]
        validators = [f"VAL-0{i}" for i in range(1, 6)]
        sender = "SENDER-HQ"

        for r in recipients:
            self.register_recipient(r)
        for v in validators:
            self.register_validator(v)
        self.register_sender(sender)

        return self.get_public_registry()
