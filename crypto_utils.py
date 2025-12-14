"""SecureTalk cryptographic primitives.

Hybrid encryption design (per project doc):
- Encrypt message/file contents with a fresh symmetric key (AES).
- Encrypt (wrap) that AES session key with recipient's public key (RSA/ECC).
- Optional digital signatures for sender authentication/integrity.

This reference implementation uses:
- AES-256-GCM (content encryption)
- RSA-OAEP(SHA-256) (key wrapping)
- RSA-PSS(SHA-256) (signatures)

Note: ECC support could be added later (e.g., ECDH + HKDF for key exchange, ECDSA for signing).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------
# Key generation & storage
# -------------------------

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Return (private_pem, public_pem)."""
    if key_size < 2048:
        raise ValueError("RSA key_size must be >= 2048")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt_private_key_pem(private_pem: bytes, passphrase: str) -> bytes:
    """Encrypt PKCS8 private key PEM with a passphrase."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def load_private_key(private_pem: bytes, passphrase: Optional[str] = None):
    return serialization.load_pem_private_key(
        private_pem, password=(passphrase.encode("utf-8") if passphrase else None)
    )


def load_public_key(public_pem: bytes):
    return serialization.load_pem_public_key(public_pem)


# -------------------------
# Hybrid encryption structs
# -------------------------

@dataclass
class HybridCiphertext:
    enc_session_key: bytes  # RSA-OAEP encrypted AES key
    nonce: bytes            # AESGCM nonce (12 bytes)
    ciphertext: bytes       # AESGCM ciphertext (includes auth tag at end)

    def to_b64_dict(self) -> dict:
        return {
            "enc_session_key": base64.b64encode(self.enc_session_key).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @staticmethod
    def from_b64_dict(d: dict) -> "HybridCiphertext":
        return HybridCiphertext(
            enc_session_key=base64.b64decode(d["enc_session_key"]),
            nonce=base64.b64decode(d["nonce"]),
            ciphertext=base64.b64decode(d["ciphertext"]),
        )


# -------------------------
# Encrypt / decrypt content
# -------------------------

def hybrid_encrypt(plaintext: bytes, recipient_public_pem: bytes, aad: bytes = b"") -> HybridCiphertext:
    """Encrypt plaintext with fresh AES-256-GCM key, wrap key with recipient RSA public key."""
    session_key = os.urandom(32)  # AES-256
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)        # recommended nonce length for AESGCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    pub = load_public_key(recipient_public_pem)
    enc_session_key = pub.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return HybridCiphertext(enc_session_key=enc_session_key, nonce=nonce, ciphertext=ciphertext)


def hybrid_decrypt(h: HybridCiphertext, recipient_private_pem: bytes, passphrase: Optional[str] = None, aad: bytes = b"") -> bytes:
    """Unwrap session key with recipient RSA private key, decrypt AES-256-GCM."""
    priv = load_private_key(recipient_private_pem, passphrase)
    session_key = priv.decrypt(
        h.enc_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(h.nonce, h.ciphertext, aad)


# -------------------------
# Optional signatures
# -------------------------

def sign_payload(payload: bytes, sender_private_pem: bytes, passphrase: Optional[str] = None) -> bytes:
    priv = load_private_key(sender_private_pem, passphrase)
    return priv.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(payload: bytes, signature: bytes, sender_public_pem: bytes) -> bool:
    pub = load_public_key(sender_public_pem)
    try:
        pub.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def stable_signing_payload(*parts: bytes) -> bytes:
    """Create a canonical payload to sign/verify. Avoids JSON reordering issues."""
    sep = b"\x1f"  # unit separator
    return sep.join(parts)
