# SPDX-License-Identifier: Apache-2.0
"""Noise_IKpsk2_25519_ChaChaPoly_SHA256, Noise revision 34 (§4.4).

The prologue MUST be the 25-byte FirstPacket header exactly as transmitted
(§4.4, §7.2). Handshake payload rules (§4.4): zero-length everywhere except
message 1 of a brokered connection, which is exactly the 16-byte service_id.
"""

import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import crypto
from .constants import NOISE_PROTOCOL_NAME
from .errors import HandshakeError

_SERVICE_ID_LEN = 16


def _sha256(d: bytes) -> bytes:
    return hashlib.sha256(d).digest()


def _hkdf(ck: bytes, ikm: bytes, n: int):
    temp = crypto.hmac_sha256(ck, ikm)
    o1 = crypto.hmac_sha256(temp, b"\x01")
    o2 = crypto.hmac_sha256(temp, o1 + b"\x02")
    if n == 2:
        return o1, o2
    return o1, o2, crypto.hmac_sha256(temp, o2 + b"\x03")


class CipherState:
    """Noise CipherState. ChaChaPoly nonce is 4 zero bytes || n little-endian."""

    def __init__(self):
        self.k, self.n = None, 0

    def initialize_key(self, k: bytes):
        self.k, self.n = k, 0

    def _nonce(self) -> bytes:
        return b"\x00" * 4 + self.n.to_bytes(8, "little")

    def encrypt(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        ct = ChaCha20Poly1305(self.k).encrypt(self._nonce(), plaintext, ad)
        self.n += 1
        return ct

    def decrypt(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        try:
            pt = ChaCha20Poly1305(self.k).decrypt(self._nonce(), ciphertext, ad)
        except InvalidTag as exc:
            raise HandshakeError("aead_failure") from exc
        self.n += 1
        return pt


class SymmetricState:
    def __init__(self, name: bytes):
        self.h = name.ljust(32, b"\x00") if len(name) <= 32 else _sha256(name)
        self.ck = self.h
        self.cs = CipherState()

    def mix_key(self, ikm: bytes):
        self.ck, temp_k = _hkdf(self.ck, ikm, 2)
        self.cs.initialize_key(temp_k)

    def mix_hash(self, data: bytes):
        self.h = _sha256(self.h + data)

    def mix_key_and_hash(self, ikm: bytes):
        self.ck, temp_h, temp_k = _hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cs.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cs.encrypt(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cs.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        t1, t2 = _hkdf(self.ck, b"", 2)
        c1, c2 = CipherState(), CipherState()
        c1.initialize_key(t1)
        c2.initialize_key(t2)
        return c1, c2


class Handshake:
    """IKpsk2 handshake state for one connection.

    Pattern:  <- s  ...  -> e, es, s, ss   <- e, ee, se, psk
    In psk mode every "e" token also calls MixKey(e.public_key).
    """

    _PATTERNS = (("e", "es", "s", "ss"), ("e", "ee", "se", "psk"))

    def __init__(
        self,
        *,
        initiator: bool,
        prologue: bytes,
        static_private: bytes,
        psk: bytes,
        remote_static: bytes | None = None,
        ephemeral_private: bytes | None = None,
    ):
        if initiator and remote_static is None:
            raise HandshakeError("initiator requires responder static key (IK pre-message)")
        self.ss = SymmetricState(NOISE_PROTOCOL_NAME)
        self.initiator = initiator
        self.s_priv = static_private
        self.s_pub = crypto.public_key(static_private)
        self.e_priv = ephemeral_private if ephemeral_private is not None else crypto.generate_private_key()
        self.e_pub = crypto.public_key(self.e_priv)
        self.rs = remote_static
        self.re = None
        self.psk = psk
        self.idx = 0
        self.ss.mix_hash(prologue)
        self.ss.mix_hash(remote_static if initiator else self.s_pub)  # pre-message: <- s

    @property
    def finished(self) -> bool:
        return self.idx == 2

    @property
    def handshake_hash(self) -> bytes:
        if not self.finished:
            raise HandshakeError("handshake not complete")
        return self.ss.h

    @property
    def remote_static(self) -> bytes | None:
        return self.rs

    def _my_turn_to_write(self) -> bool:
        return (self.idx % 2 == 0) == self.initiator

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.finished or not self._my_turn_to_write():
            raise HandshakeError("out_of_order")
        buf = b""
        for tok in self._PATTERNS[self.idx]:
            if tok == "e":
                buf += self.e_pub
                self.ss.mix_hash(self.e_pub)
                self.ss.mix_key(self.e_pub)  # psk mode
            elif tok == "s":
                buf += self.ss.encrypt_and_hash(self.s_pub)
            elif tok == "es":
                self.ss.mix_key(crypto.dh(self.e_priv, self.rs) if self.initiator else crypto.dh(self.s_priv, self.re))
            elif tok == "se":
                self.ss.mix_key(crypto.dh(self.s_priv, self.re) if self.initiator else crypto.dh(self.e_priv, self.rs))
            elif tok == "ee":
                self.ss.mix_key(crypto.dh(self.e_priv, self.re))
            elif tok == "ss":
                self.ss.mix_key(crypto.dh(self.s_priv, self.rs))
            elif tok == "psk":
                self.ss.mix_key_and_hash(self.psk)
        buf += self.ss.encrypt_and_hash(payload)
        self.idx += 1
        return buf

    def read_message(self, message: bytes) -> bytes:
        if self.finished or self._my_turn_to_write():
            raise HandshakeError("out_of_order")
        off = 0
        for tok in self._PATTERNS[self.idx]:
            if tok == "e":
                if len(message) < off + 32:
                    raise HandshakeError("truncated")
                self.re = message[off : off + 32]
                off += 32
                self.ss.mix_hash(self.re)
                self.ss.mix_key(self.re)
            elif tok == "s":
                ln = 48 if self.ss.cs.k is not None else 32
                if len(message) < off + ln:
                    raise HandshakeError("truncated")
                self.rs = self.ss.decrypt_and_hash(message[off : off + ln])
                off += ln
            elif tok == "es":
                self.ss.mix_key(crypto.dh(self.e_priv, self.rs) if self.initiator else crypto.dh(self.s_priv, self.re))
            elif tok == "se":
                self.ss.mix_key(crypto.dh(self.s_priv, self.re) if self.initiator else crypto.dh(self.e_priv, self.rs))
            elif tok == "ee":
                self.ss.mix_key(crypto.dh(self.e_priv, self.re))
            elif tok == "ss":
                self.ss.mix_key(crypto.dh(self.s_priv, self.rs))
            elif tok == "psk":
                self.ss.mix_key_and_hash(self.psk)
        payload = self.ss.decrypt_and_hash(message[off:])
        self.idx += 1
        return payload

    def split(self) -> tuple[CipherState, CipherState]:
        """Transport cipher states as (send, receive) for this party (§4.4)."""
        if not self.finished:
            raise HandshakeError("handshake not complete")
        c1, c2 = self.ss.split()
        return (c1, c2) if self.initiator else (c2, c1)


def check_message1_payload(payload: bytes, *, brokered: bool):
    """§4.4: direct message 1 payload MUST be empty; brokered MUST be exactly
    the 16-byte service_id. Violations abort the handshake silently."""
    expected = _SERVICE_ID_LEN if brokered else 0
    if len(payload) != expected:
        raise HandshakeError("message1_payload_length")


def check_message2_payload(payload: bytes):
    """§4.4: message 2 payload MUST be zero-length."""
    if payload != b"":
        raise HandshakeError("message2_payload_length")
