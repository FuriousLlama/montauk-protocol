# SPDX-License-Identifier: Apache-2.0
"""Generates the Montauk spec test vectors for Sections 13.1-13.4.

Self-contained, standard library only. The X25519 implementation follows the
RFC 7748 pseudocode and is validated against the RFC 7748 Section 6.1 test
vector at every run before any Montauk value is computed.

Every value printed here appears verbatim in montauk_spec.md Section 13.
Regenerate after any change to the derivation (Section 6) and update the spec.
Run export_vectors.py to refresh the machine-readable vectors.json.
"""
import datetime
import hashlib
import hmac
import ipaddress

P = 2**255 - 19


def _decode_scalar(kb):
    k = bytearray(kb)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _decode_u(ub):
    u = bytearray(ub)
    u[31] &= 127
    return int.from_bytes(u, "little")


def x25519(kb, ub):
    """RFC 7748 X25519 scalar multiplication (Montgomery ladder)."""
    k = _decode_scalar(kb)
    x1 = _decode_u(ub)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = pow(DA + CB, 2, P)
        z3 = x1 * pow(DA - CB, 2, P) % P
        x2 = AA * BB % P
        z2 = E * (AA + 121665 * E) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def hkdf_sha256(ikm, salt, info, L=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:L]


def compute_address(session_key, responder_pubkey, prefix_str, service_id, T):
    """Section 6.3 address computation."""
    net = ipaddress.IPv6Network(prefix_str)
    inp = T.to_bytes(8, "big") + b"montauk-v1-address" + responder_pubkey + service_id
    raw = hmac.new(session_key, inp, hashlib.sha256).digest()
    host_mask = (1 << (128 - net.prefixlen)) - 1
    addr = ipaddress.IPv6Address(int(net.network_address) | (int.from_bytes(raw[:16], "big") & host_mask))
    port_raw = (raw[16] << 8) | raw[17]
    return raw, addr, port_raw, 1024 + (port_raw % 64511)


def grouped(b):
    h = b.hex()
    return " ".join(h[i : i + 16] for i in range(0, len(h), 16))


# RFC 7748 Section 6.1 test material (doubles as the spec's 13.2 keys)
alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
alice_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

prior = bytes.fromhex("deadbeefcafebabe0123456789abcdeffedcba9876543210baadf00ddeadbeef")
service_id = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

ADDRESS_CASES = [
    ("A", "A (/64)", "2001:db8:1234:5678::/64", 5687652),
    ("B", "B (/80)", "2001:db8:1234:5678:9abc::/80", 5687652),
    ("C", "C (port modulo)", "2001:db8:1234:5678::/64", 5687738),
]


def vectors():
    """Compute the Section 13.1-13.4 vectors as a structured dict.

    Fail-closed: asserts the RFC 7748 Section 6.1 vector before computing
    anything Montauk-specific.
    """
    assert x25519(alice_priv, BASE) == alice_pub
    assert x25519(bob_priv, BASE) == bob_pub
    assert x25519(alice_priv, bob_pub) == shared
    assert x25519(bob_priv, alice_pub) == shared

    seed = bytes(range(32))
    session_key = hkdf_sha256(shared, prior, b"montauk-v1-session")

    cases = []
    for name, label, prefix, T in ADDRESS_CASES:
        raw, addr, port_raw, port = compute_address(session_key, bob_pub, prefix, service_id, T)
        cases.append(
            {
                "name": name,
                "label": label,
                "prefix": prefix,
                "T": T,
                "timestamp": T * 300,
                "raw": raw.hex(),
                "ipv6_address": addr.compressed,
                "port_raw": port_raw,
                "port": port,
            }
        )

    return {
        "key_generation": {
            "section": "13.1",
            "inputs": {"private_key": seed.hex()},
            "outputs": {"public_key": x25519(seed, BASE).hex()},
        },
        "shared_secret": {
            "section": "13.2",
            "inputs": {
                "alice_private": alice_priv.hex(),
                "bob_private": bob_priv.hex(),
                "alice_public": alice_pub.hex(),
                "bob_public": bob_pub.hex(),
            },
            "outputs": {"shared_secret": shared.hex()},
        },
        "session_key": {
            "section": "13.3",
            "inputs": {"shared_secret": shared.hex(), "prior": prior.hex()},
            "outputs": {"session_key": session_key.hex()},
        },
        "address_generation": {
            "section": "13.4",
            "common": {
                "session_key": session_key.hex(),
                "responder_pubkey": bob_pub.hex(),
                "service_id": service_id.hex(),
            },
            "cases": cases,
        },
    }


def main():
    v = vectors()
    print("X25519 validated against RFC 7748 Section 6.1")
    print("\n[13.1] public_key =", v["key_generation"]["outputs"]["public_key"])
    print("[13.2] shared_secret =", v["shared_secret"]["outputs"]["shared_secret"])
    print("[13.3] session_key =", grouped(bytes.fromhex(v["session_key"]["outputs"]["session_key"])))
    for c in v["address_generation"]["cases"]:
        ts = c["timestamp"]
        utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        print(f"\n[13.4] Vector {c['label']}  prefix={c['prefix']}  T={c['T']} (timestamp {ts} = {utc:%Y-%m-%d %H:%M} UTC)")
        print("       raw  =", grouped(bytes.fromhex(c["raw"])))
        print("       addr =", c["ipv6_address"])
        print(f"       port = {c['port']}  (port_raw = {c['port_raw']} = {c['port_raw']:#06x})")


if __name__ == "__main__":
    main()
