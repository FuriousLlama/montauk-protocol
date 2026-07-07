"""Generates the Montauk spec test vectors for Sections 13.1-13.4.

Self-contained, standard library only. The X25519 implementation follows the
RFC 7748 pseudocode and is validated against the RFC 7748 Section 6.1 test
vector at every run before any Montauk value is computed.

Every value printed here appears verbatim in montauk_spec.md Section 13.
Regenerate after any change to the derivation (Section 6) and update the spec.
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


# --- Validate X25519 against RFC 7748 Section 6.1 ---
alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
alice_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
assert x25519(alice_priv, BASE) == alice_pub
assert x25519(bob_priv, BASE) == bob_pub
assert x25519(alice_priv, bob_pub) == shared
assert x25519(bob_priv, alice_pub) == shared
print("X25519 validated against RFC 7748 Section 6.1")

# --- 13.1 Key Generation ---
seed = bytes(range(32))
print("\n[13.1] public_key =", x25519(seed, BASE).hex())

# --- 13.2 Shared Secret (the RFC 7748 vector itself) ---
print("[13.2] shared_secret =", shared.hex())

# --- 13.3 Session Key Derivation ---
prior = bytes.fromhex("deadbeefcafebabe0123456789abcdeffedcba9876543210baadf00ddeadbeef")
session_key = hkdf_sha256(shared, prior, b"montauk-v1-session")
print("[13.3] session_key =", grouped(session_key))

# --- 13.4 Address Generation ---
service_id = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

for label, prefix, T in [
    ("A (/64)", "2001:db8:1234:5678::/64", 5687652),
    ("B (/80)", "2001:db8:1234:5678:9abc::/80", 5687652),
    ("C (port modulo)", "2001:db8:1234:5678::/64", 5687738),
]:
    raw, addr, port_raw, port = compute_address(session_key, bob_pub, prefix, service_id, T)
    ts = T * 300
    utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    print(f"\n[13.4] Vector {label}  prefix={prefix}  T={T} (timestamp {ts} = {utc:%Y-%m-%d %H:%M} UTC)")
    print("       raw  =", grouped(raw))
    print("       addr =", addr.compressed)
    print(f"       port = {port}  (port_raw = {port_raw} = {port_raw:#06x})")
