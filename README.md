# Montauk Protocol

The protocol allows for the exchange of information by allowing two parties to set a predefined location for communication.

Using a Prior, two agents compute a valid location for exchanging communication while making it highly unlikely to be 'guessed' by chance.

# Status

- **Specification:** v0.4.0-draft. Folds in the findings from building and
  validating the reference implementation; no wire formats or test vectors
  changed since v0.3.0 (see Appendix C of the spec).
- **Reference implementation:** v1 complete (milestones M0–M5). Direct and
  brokered connections, live address rotation, and the nftables firewall were
  validated cross-host on an isolated IPv6 testbed. 66 tests, all green.
- **Review:** an independent adversarial review of the spec against the
  implementation and a line-by-line §12.1 conformance audit are recorded in
  the roadmap; every finding is fixed or documented.

# Specification

The specification is stored in [montauk spec](montauk_spec.md).

# Test Vectors

The generators for the specification's test vectors (Section 13), including
their validation against RFC 7748 and the official Noise test vectors, live
in [reference/](reference/).

# Reference Implementation

The Python reference implementation lives in [impl/](impl/), with its own
[README](impl/README.md) covering the `montauk` CLI, layout, and loopback
testing.

- [docs/reference_roadmap.md](docs/reference_roadmap.md) — architecture,
  milestones, the spec-feedback log, the independent review, and the §12.1
  conformance audit.
- [docs/deployment.md](docs/deployment.md) — deploying a responder, initiator,
  and broker on real hosts (AnyIP, `IPV6_FREEBIND`, nftables).

# License

- **Code** (`reference/`, `impl/`): copyright 2026
  Manuel Rodriguez, licensed under the [Apache License 2.0](LICENSE).
- **Specification text** (`montauk_spec.md`, `docs/`):
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **Test vectors** (Section 13 of the spec and generated vector files):
  dedicated to the public domain under
  [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

The vendored Noise test vector in `reference/cacophony_ikpsk2.json` comes
from the [cacophony](https://github.com/haskell-cryptography/cacophony)
project, which is public domain.
