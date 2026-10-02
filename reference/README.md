# Reference Vector Generators

Code that generates (and re-verifies) every test vector in
[montauk_spec.md](../montauk_spec.md) Section 13. This is vector-generation
and verification tooling, not the sample implementation.

| File | Generates | Dependencies |
| ---- | --------- | ------------ |
| `vectors_address.py` | §13.1–13.4 (keys, shared secret, session key, addresses) | Python 3.10+, stdlib only |
| `vectors_handshake.py` | §13.5–13.7 (First Packet, handshake transcripts) | `pip install cryptography` |
| `export_vectors.py` | `vectors.json` — machine-readable export of every vector | `pip install cryptography` |
| `vectors.json` | — (generated output; consumed by `impl/tests` and other implementations) | — |
| `cacophony_ikpsk2.json` | — (ground-truth data) | vendored from the [cacophony](https://github.com/haskell-cryptography/cacophony) project |

## Running

```
python3 vectors_address.py
pip install cryptography && python3 vectors_handshake.py
python3 export_vectors.py   # refreshes vectors.json
```

## Validation chain

Nothing is generated unless the implementation first reproduces external
ground truth at runtime:

1. `vectors_address.py` implements X25519 from the RFC 7748 pseudocode and
   asserts the RFC 7748 §6.1 test vector (both public keys, shared secret
   from both sides) before computing anything.
2. `vectors_handshake.py` implements Noise_IKpsk2_25519_ChaChaPoly_SHA256
   (Noise revision 34) and asserts the official cacophony test vector for
   that exact protocol name — both handshake messages, all four transport
   messages, and the handshake hash, byte-for-byte — before computing
   anything.

## Keeping the spec in sync

Every value these scripts print appears verbatim in the spec. After any
change to address derivation (§6) or the handshake (§4.4, §7), rerun both
scripts, update §13 to match, and rerun `export_vectors.py` so
`vectors.json` (and therefore the implementation's golden tests) stays in
lockstep.

## License

Generator code is Apache-2.0 (see the repository [LICENSE](../LICENSE)).
Generated vectors are dedicated to the public domain under CC0 1.0. The
vendored `cacophony_ikpsk2.json` comes from the public-domain
[cacophony](https://github.com/haskell-cryptography/cacophony) project.
