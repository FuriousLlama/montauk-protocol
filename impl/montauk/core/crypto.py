# SPDX-License-Identifier: Apache-2.0
"""Cryptographic primitives (§4.1-§4.3, §6.2)."""

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .constants import SESSION_INFO
from .errors import MontaukError


def generate_private_key() -> bytes:
    """New X25519 private key (§4.1)."""
    return X25519PrivateKey.generate().private_bytes_raw()


def public_key(private: bytes) -> bytes:
    """X25519 public key for a private key (§4.1)."""
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def dh(private: bytes, public: bytes) -> bytes:
    """X25519 shared secret (§4.1). MUST NOT be all-zero."""
    shared = X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(public)
    )
    if shared == bytes(32):
        raise MontaukError("all-zero shared secret")
    return shared


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF per RFC 5869 (§4.2)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_session_key(shared_secret: bytes, prior: bytes) -> bytes:
    """Session key for a relationship (§6.2)."""
    return hkdf_sha256(shared_secret, salt=prior, info=SESSION_INFO)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """PRF for address generation (§4.3)."""
    return hmac.new(key, data, hashlib.sha256).digest()
