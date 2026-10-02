# SPDX-License-Identifier: Apache-2.0
"""Generates the Montauk spec test vectors for Sections 13.5-13.7.

Implements Noise_IKpsk2_25519_ChaChaPoly_SHA256 (Noise revision 34). Before
generating any Montauk value, the stack must reproduce the official cacophony
test vector for this exact protocol name byte-for-byte (both handshake
messages, all four transport messages, and the handshake hash); the vendored
vector lives in cacophony_ikpsk2.json next to this file.

Requires: pip install cryptography

Every value printed here appears verbatim in montauk_spec.md Section 13.
Regenerate after any change to the handshake (Sections 4.4, 7) and update
the spec. Run export_vectors.py to refresh the machine-readable vectors.json.
"""
import hashlib
import hmac as hmac_mod
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_SHA256"


def sha256(d):
    return hashlib.sha256(d).digest()


def hmac(k, d):
    return hmac_mod.new(k, d, hashlib.sha256).digest()


def hkdf(ck, ikm, n):
    temp = hmac(ck, ikm)
    o1 = hmac(temp, b"\x01")
    o2 = hmac(temp, o1 + b"\x02")
    if n == 2:
        return o1, o2
    return o1, o2, hmac(temp, o2 + b"\x03")


def dh(priv, pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def pubkey(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()


class CipherState:
    def __init__(self):
        self.k, self.n = None, 0

    def initialize_key(self, k):
        self.k, self.n = k, 0

    def _nonce(self):
        return b"\x00" * 4 + self.n.to_bytes(8, "little")

    def encrypt(self, ad, pt):
        if self.k is None:
            return pt
        ct = ChaCha20Poly1305(self.k).encrypt(self._nonce(), pt, ad)
        self.n += 1
        return ct

    def decrypt(self, ad, ct):
        if self.k is None:
            return ct
        pt = ChaCha20Poly1305(self.k).decrypt(self._nonce(), ct, ad)
        self.n += 1
        return pt


class SymmetricState:
    def __init__(self, name):
        self.h = name.ljust(32, b"\x00") if len(name) <= 32 else sha256(name)
        self.ck = self.h
        self.cs = CipherState()

    def mix_key(self, ikm):
        self.ck, temp_k = hkdf(self.ck, ikm, 2)
        self.cs.initialize_key(temp_k)

    def mix_hash(self, data):
        self.h = sha256(self.h + data)

    def mix_key_and_hash(self, ikm):
        self.ck, temp_h, temp_k = hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cs.initialize_key(temp_k)

    def encrypt_and_hash(self, pt):
        ct = self.cs.encrypt(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct):
        pt = self.cs.decrypt(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self):
        t1, t2 = hkdf(self.ck, b"", 2)
        c1, c2 = CipherState(), CipherState()
        c1.initialize_key(t1)
        c2.initialize_key(t2)
        return c1, c2


class IKpsk2:
    # IK: <- s ... -> e, es, s, ss  <- e, ee, se, psk (psk2 modifier)
    PATTERNS = [["e", "es", "s", "ss"], ["e", "ee", "se", "psk"]]

    def __init__(self, initiator, prologue, s_priv, e_priv, rs_pub, psk):
        self.ss = SymmetricState(PROTOCOL_NAME)
        self.initiator = initiator
        self.s_priv, self.s_pub = s_priv, pubkey(s_priv)
        self.e_priv, self.e_pub = e_priv, pubkey(e_priv)
        self.rs, self.re = rs_pub, None
        self.psk = psk
        self.idx = 0
        self.ss.mix_hash(prologue)
        self.ss.mix_hash(rs_pub if initiator else self.s_pub)  # pre-message: <- s

    def write(self, payload):
        buf = b""
        for tok in self.PATTERNS[self.idx]:
            if tok == "e":
                buf += self.e_pub
                self.ss.mix_hash(self.e_pub)
                self.ss.mix_key(self.e_pub)  # psk mode: e also mixes key
            elif tok == "s":
                buf += self.ss.encrypt_and_hash(self.s_pub)
            elif tok == "es":
                self.ss.mix_key(dh(self.e_priv, self.rs) if self.initiator else dh(self.s_priv, self.re))
            elif tok == "se":
                self.ss.mix_key(dh(self.s_priv, self.re) if self.initiator else dh(self.e_priv, self.rs))
            elif tok == "ee":
                self.ss.mix_key(dh(self.e_priv, self.re))
            elif tok == "ss":
                self.ss.mix_key(dh(self.s_priv, self.rs))
            elif tok == "psk":
                self.ss.mix_key_and_hash(self.psk)
        buf += self.ss.encrypt_and_hash(payload)
        self.idx += 1
        return buf

    def read(self, msg):
        off = 0
        for tok in self.PATTERNS[self.idx]:
            if tok == "e":
                self.re = msg[off : off + 32]
                off += 32
                self.ss.mix_hash(self.re)
                self.ss.mix_key(self.re)
            elif tok == "s":
                ln = 48 if self.ss.cs.k is not None else 32
                self.rs = self.ss.decrypt_and_hash(msg[off : off + ln])
                off += ln
            elif tok == "es":
                self.ss.mix_key(dh(self.e_priv, self.rs) if self.initiator else dh(self.s_priv, self.re))
            elif tok == "se":
                self.ss.mix_key(dh(self.s_priv, self.re) if self.initiator else dh(self.e_priv, self.rs))
            elif tok == "ee":
                self.ss.mix_key(dh(self.e_priv, self.re))
            elif tok == "ss":
                self.ss.mix_key(dh(self.s_priv, self.rs))
            elif tok == "psk":
                self.ss.mix_key_and_hash(self.psk)
        payload = self.ss.decrypt_and_hash(msg[off:])
        self.idx += 1
        return payload


def run_handshake(prologue, i_s, i_e, r_s, r_e, psk, payload1, payload2):
    init = IKpsk2(True, prologue, i_s, i_e, pubkey(r_s), psk)
    resp = IKpsk2(False, prologue, r_s, r_e, None, psk)
    m1 = init.write(payload1)
    assert resp.read(m1) == payload1
    m2 = resp.write(payload2)
    assert init.read(m2) == payload2
    assert init.ss.h == resp.ss.h
    i_send, i_recv = init.ss.split()
    r_recv, r_send = resp.ss.split()
    return m1, m2, init.ss.h, (i_send, i_recv, r_send, r_recv)


def grouped(b, indent=10):
    h = b.hex()
    lines = [" ".join(h[j : j + 16] for j in range(i, min(i + 64, len(h)), 16)) for i in range(0, len(h), 64)]
    return ("\n" + " " * indent).join(lines)


def _validate_against_cacophony():
    vec = json.loads((Path(__file__).parent / "cacophony_ikpsk2.json").read_text())["vector"]
    fx = bytes.fromhex
    m1, m2, hh, (i_send, i_recv, r_send, r_recv) = run_handshake(
        fx(vec["init_prologue"]), fx(vec["init_static"]), fx(vec["init_ephemeral"]),
        fx(vec["resp_static"]), fx(vec["resp_ephemeral"]), fx(vec["init_psks"][0]),
        fx(vec["messages"][0]["payload"]), fx(vec["messages"][1]["payload"]),
    )
    assert m1 == fx(vec["messages"][0]["ciphertext"]), "cacophony msg1 mismatch"
    assert m2 == fx(vec["messages"][1]["ciphertext"]), "cacophony msg2 mismatch"
    assert hh == fx(vec["handshake_hash"]), "cacophony handshake hash mismatch"
    for i, msg in enumerate(vec["messages"][2:]):
        sender = i_send if i % 2 == 0 else r_send
        assert sender.encrypt(b"", fx(msg["payload"])) == fx(msg["ciphertext"]), f"cacophony transport {i} mismatch"


# Montauk transcript inputs (Sections 13.5-13.7)
fx = bytes.fromhex
alice_priv = fx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
bob_priv = fx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
init_eph = fx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")  # Section 13.1 key
resp_eph = fx("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
psk = fx("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
service_id = fx("0f0e0d0c0b0a09080706050403020100")
TIMESTAMP = 1706295600
NONCE_DIRECT = bytes(range(16))
NONCE_BROKERED = bytes(range(16, 32))


def vectors():
    """Compute the Section 13.5-13.7 vectors as a structured dict.

    Fail-closed: reproduces the official cacophony IKpsk2 vector before
    computing anything Montauk-specific.
    """
    _validate_against_cacophony()
    ts8 = TIMESTAMP.to_bytes(8, "big")
    out = {}
    for key, section, nonce, p1 in [
        ("handshake_direct", "13.6", NONCE_DIRECT, b""),
        ("handshake_brokered", "13.7", NONCE_BROKERED, service_id),
    ]:
        prologue = b"\x01" + ts8 + nonce
        m1, m2, hh, (i_send, i_recv, r_send, r_recv) = run_handshake(
            prologue, alice_priv, init_eph, bob_priv, resp_eph, psk, p1, b""
        )
        entry = {
            "section": section,
            "inputs": {
                "init_static": alice_priv.hex(),
                "resp_static": bob_priv.hex(),
                "init_ephemeral": init_eph.hex(),
                "resp_ephemeral": resp_eph.hex(),
                "resp_ephemeral_pub": pubkey(resp_eph).hex(),
                "psk": psk.hex(),
                "prologue": prologue.hex(),
                "msg1_payload": p1.hex(),
                "msg2_payload": "",
            },
            "outputs": {
                "message_1": m1.hex(),
                "message_2": m2.hex(),
                "handshake_hash": hh.hex(),
            },
        }
        if key == "handshake_direct":
            t1 = i_send.encrypt(b"", b"ping")
            t2 = r_send.encrypt(b"", b"pong")
            entry["outputs"]["transport_1"] = {"plaintext": b"ping".hex(), "ciphertext": t1.hex()}
            entry["outputs"]["transport_2"] = {"plaintext": b"pong".hex(), "ciphertext": t2.hex()}
            frame_body = b"\x01" + ts8 + NONCE_DIRECT + m1
            out["first_packet"] = {
                "section": "13.5",
                "inputs": {
                    "version": 1,
                    "timestamp": TIMESTAMP,
                    "nonce": NONCE_DIRECT.hex(),
                    "payload": m1.hex(),
                },
                "outputs": {
                    "frame_body": frame_body.hex(),
                    "wire_format": (len(frame_body).to_bytes(2, "big") + frame_body).hex(),
                    "noise_prologue": frame_body[:25].hex(),
                },
            }
        out[key] = entry
    return out


def main():
    v = vectors()
    print("Noise stack validated against the official cacophony IKpsk2 vector (byte-for-byte)")
    print("resp_ephemeral_pub =", v["handshake_direct"]["inputs"]["resp_ephemeral_pub"])
    for key, label in [("handshake_direct", "DIRECT"), ("handshake_brokered", "BROKERED")]:
        e = v[key]
        m1 = bytes.fromhex(e["outputs"]["message_1"])
        m2 = bytes.fromhex(e["outputs"]["message_2"])
        print(f"\n[{e['section']}] {label}")
        print("  prologue =", e["inputs"]["prologue"])
        print(f"  noise_message_1 ({len(m1)} bytes) =")
        print("         ", grouped(m1))
        print(f"  noise_message_2 ({len(m2)} bytes) =")
        print("         ", grouped(m2))
        print("  handshake_hash =")
        print("         ", grouped(bytes.fromhex(e["outputs"]["handshake_hash"])))
        print(f"  first_packet frame body = {25 + len(m1)} bytes (0x{25 + len(m1):04x}), msg2 frame = 0x{len(m2):04x}")
        if key == "handshake_direct":
            t1 = bytes.fromhex(e["outputs"]["transport_1"]["ciphertext"])
            t2 = bytes.fromhex(e["outputs"]["transport_2"]["ciphertext"])
            print(f'  transport_1 init->resp "ping" ({len(t1)} bytes) =')
            print("         ", grouped(t1))
            print(f'  transport_2 resp->init "pong" ({len(t2)} bytes) =')
            print("         ", grouped(t2))


if __name__ == "__main__":
    main()
