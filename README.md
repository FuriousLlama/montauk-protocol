# Montauk Protocol

The protocol allows for the exchange of information by allowing two parties to set a predefined location for communication.

Using a Prior, two agents compute a valid location for exchanging communication while making it highly unlikely to be 'guessed' by chance.

# Specification

The specification is stored in [montauk spec](montauk_spec.md).

# Test Vectors

The generators for the specification's test vectors (Section 13), including
their validation against RFC 7748 and the official Noise test vectors, live
in [reference/](reference/).

# Reference Implementation

The roadmap for the reference implementation — architecture, milestones,
testing strategy, and the running spec-feedback log — is in
[docs/reference_roadmap.md](docs/reference_roadmap.md).

# License

- **Code** (`reference/`, future implementation directories): copyright 2026
  Manuel Rodriguez, licensed under the [Apache License 2.0](LICENSE).
- **Specification text** (`montauk_spec.md`, `docs/`):
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **Test vectors** (Section 13 of the spec and generated vector files):
  dedicated to the public domain under
  [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

The vendored Noise test vector in `reference/cacophony_ikpsk2.json` comes
from the [cacophony](https://github.com/haskell-cryptography/cacophony)
project, which is public domain.
