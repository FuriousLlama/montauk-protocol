---
title: "Montauk Reference Implementation Roadmap"
status: "Living document"
targets: "montauk_spec.md v0.3.0-draft"
date: "2026-07-06"
---

# Reference Implementation Roadmap

## 1. Purpose

The reference implementation has three jobs, in priority order:

1. **Executable spec** — someone confused by a section of the spec reads the
   corresponding module and is unconfused. Clarity beats performance
   everywhere; module boundaries mirror spec section boundaries.
2. **Conformance oracle** — future implementations test against it and its
   vectors. Interoperating with the reference is the definition of
   conforming, until a second independent implementation exists.
3. **Spec-bug detector** — writing it is the final review pass. Code cannot
   leave ambiguities unresolved the way prose can. Every place the code is
   forced to make a decision the spec does not make is logged in Section 8
   and becomes a spec patch.

## 2. Language and Codebase Strategy

**Python for the reference; Go or Rust for the production tool later, as a
separate codebase.**

Rationale:

- The validated crypto stack already exists in `reference/` (Noise IKpsk2
  classes, address derivation) — it is most of a sans-IO protocol core.
- `asyncio` fits the concurrency shape (listener churn, keepalives, bridges)
  without threads.
- Iteration speed matters most while the spec is still moving.
- The later production port is a feature, not waste: two independent
  implementations passing the same vectors and interoperating with each
  other is the real conformance milestone.

The vector generators in `reference/` stay frozen in their current role
(spec tooling with fail-closed validation gates). The implementation copies
the crypto it needs rather than importing from them, so the generators never
drift under the implementation's feet.

Proposed layout:

```
montauk-protocol/
├── montauk_spec.md
├── docs/
│   ├── reference_roadmap.md    this document
│   └── deployment.md           written during M3-M4
├── reference/                  vector generators (unchanged role)
│   └── vectors.json            machine-readable export of all §13 vectors (M0)
└── impl/
    ├── montauk/
    │   ├── core/               sans-IO: crypto, engine, wire (no sockets, no clock)
    │   ├── daemon/             responder: listeners, firewall sync, proxy
    │   ├── client/             initiator: connect, local port-forward
    │   ├── broker/             phase 2
    │   └── cli.py
    └── tests/
```

## 3. Architecture: Sans-IO Core, Thin I/O Shell

The highest-leverage decision: protocol logic is **free of sockets and
clocks**. Pure state machines take bytes and an injected time value in, and
return bytes and actions out. The asyncio layer only moves bytes. This makes
the conformance suite runnable without networking and makes the eventual
production port a translation rather than a rewrite.

| Module | Responsibility | Spec |
| ------ | -------------- | ---- |
| `core/crypto` | X25519, HKDF, session keys, Noise IKpsk2 with prologue | §4, §6.2 |
| `core/engine` | Valid-set computation as a pure function of (relationships, time); emits add/remove diffs on bucket rotation | §6, §5.7 |
| `core/wire` | Framing, FirstPacket parse/validate, nonce cache, version check | §7.1–7.3, §11.3–11.5 |
| `daemon/listeners` | Bind/close sockets as engine diffs arrive (AnyIP) | §6.4 |
| `daemon/firewall` | nftables backend + null backend; element timeouts | §3.2, §11.6 |
| `daemon/handler` | validate → handshake → identify service by tuple → proxy to internal_target | §7.4, §8.2 |
| `client` | Compute peer tuple, connect, FirstPacket, expose local port-forward (`ssh -L` model) | §8.2 |
| `broker` | Control/data split, match table, keepalives, byte bridging | §7.5, §8.3, §9 |
| `cli` | Relationship import/export (JSON card first, BIP-39 later), status, revoke | §8.1, §8.4 |

Design rules:

- **Injectable clock** in every time-dependent path (bucket math, timestamp
  window, nonce expiry). Non-negotiable for testing.
- **One silent-drop funnel**: every rejection path calls the same
  `drop(reason)` function, which logs locally and never writes to the
  socket. No code path can accidentally respond (§11.5).
- **Secrets hygiene**: relationship files are 0600; priors, PSKs, and
  private keys never appear in logs or `status` output.
- `status` shows the currently live (address, port) tuples per relationship
  and service — the single most useful debugging affordance this protocol
  can offer.

## 4. Linux Integration (the make-or-break layer)

Two mechanisms make the design deployable; the reference must demonstrate
and document both. This section seeds `docs/deployment.md`.

**AnyIP** — bind any address in a prefix with zero per-address
configuration:

```
ip -6 route add local 2001:db8:1234:5678::/64 dev lo
```

Without this, rotating listeners are miserable; with it, they are trivial.
It also works with documentation prefixes on loopback, which is the test
rig: the full protocol runs end-to-end on one machine with no network.
Fallback where the route trick is unavailable: `IPV6_FREEBIND` per socket.

**nftables set with element timeouts** — one set of
`ipv6_addr . inet_service` with `flags timeout`, one accept rule, default
drop on the Montauk prefix. The daemon adds each tuple with
timeout = remaining validity. The kernel expires entries itself, which
yields **fail-closed crash safety for free**: if the daemon dies, the holes
close on their own.

**Deployment story**: primary and recommended is a *routed* prefix
(delegated or routed to the Montauk host). The on-link LAN case requires ND
proxying (`ndppd` or per-address neigh proxy churn) and is strictly worse;
document it as the secondary path, after M4.

## 5. Milestones

Each milestone ends with something you can watch work.

| # | Deliverable | Demo / acceptance |
| - | ----------- | ----------------- |
| M0 | `impl/` skeleton; crypto + engine + wire as sans-IO modules; golden tests against all §13 vectors; `reference/vectors.json` machine-readable export | Test suite green with zero sockets opened |
| M1 | Direct connection end-to-end on one machine (AnyIP on loopback, doc prefix) | Client port-forwards to a local HTTP server through a full Montauk handshake |
| M2 | Live rotation: listener manager + engine diffs on a real clock | Tuples rotate every 5 min; connection succeeds across a bucket boundary; ±skew within tolerance succeeds, outside fails |
| M3 | nftables sync + adversarial suite in network namespaces | Attacker namespace sweeps the prefix and observes zero responses; valid client connects; daemon kill test shows fail-closed expiry |
| M4 | Real deployment on an IPv6 host | SSH over Montauk as daily dogfood; `docs/deployment.md` written from the experience |
| M5 | Broker: control/data split, match_id flow, keepalives, bridging | Three namespaces (initiator, broker, responder) with NAT simulated by masquerade; end-to-end handshake through the bridge |

Rough effort at evenings-and-weekends pace: M0–M1 a few evenings (crypto
already exists), M2–M3 one to two weeks, M4 mostly ops time, M5 another
week.

## 6. Testing Strategy

- **Golden vectors**: every §13 vector, consumed from
  `reference/vectors.json`, not hand-copied hex.
- **Property tests**: address always within the advertised prefix; port
  always in [1024, 65534]; window is always exactly 3 tuples; derivation is
  deterministic across processes; framing round-trips arbitrary payloads up
  to 65535 bytes.
- **Adversarial tests**, each mapped to a spec claim:
  - Replay a captured FirstPacket verbatim → nonce cache drops it (§11.4)
  - Replay with a re-stamped header → AEAD failure in message 1 — *this is
    the test that proves the prologue decision* (§4.4)
  - Wrong PSK → message 2 fails at the initiator (§4.4)
  - Unknown version byte → silent drop (§11.5)
  - Non-empty handshake payload on a direct connection → silent abort (§4.4)
  - Prefix sweep from the attacker namespace → zero responses observed on
    the wire (§11.5)
- **Fuzzing**: the pre-auth parse surface is 25 fixed bytes plus AEAD by
  design — fuzz the frame and FirstPacket parsers anyway (hypothesis or
  atheris).
- **Harness**: network namespaces + veth. Simulates initiator, responder,
  attacker, broker, and NAT (masquerade) on one machine with packet capture.
  Integration suite may require root; that is acceptable.
- **Traceability**: adversarial and conformance tests are named after spec
  sections (`test_11_3_timestamp_window`), and the §12.1 MUST list is
  maintained as a checklist with a test per line.

## 7. Non-Goals for v1

Written down so scope creep has to argue with a document:

- Performance work of any kind (single-process asyncio is fine)
- UDP services (§5.5 protocol 0x02) — TCP only until the spec defines
  datagram semantics
- Multi-broker failover (§9.6 beyond "try in order")
- Key or relationship rotation UX
- Packaging, distro polish, non-Linux firewall backends
- GUI, mobile, IPv4/NAT64 shims

## 8. Spec Feedback Log

Decisions the code forces that the spec does not currently make. Each entry
either becomes a spec patch or is explicitly accepted as
implementation-defined.

| # | Finding | Spec impact | Status |
| - | ------- | ----------- | ------ |
| 1 | TCP SYN-ACKs before the application sees a byte, so for the *currently valid* tuple, liveness is confirmed at the kernel layer regardless of application silence. The firewall provides silence for invalid tuples; the application provides only reason-indistinguishability on valid ones. | §11.5 should state this nuance explicitly | Open |
| 2 | Behavior when a service's `internal_target` is down: close after handshake reveals liveness only to an authenticated, authorized peer. Propose: complete handshake, then close silently; never fail before handshake completion. | §7.4 or §8.2 clarification | Open |
| 3 | (address, port) collisions across streams on one host are cryptographically negligible but possible; the engine should detect and log rather than silently double-book a tuple. | Implementation-defined; possibly a §12 note | Open |
| 4 | FirstPacket timestamp validity (§11.3) and address-bucket validity (§6.4) are independent checks; a packet can arrive on a still-valid previous-bucket address with a current timestamp. Needs a test and possibly one clarifying sentence. | §11.3 note | Open |

Add to this table as they surface; every closed entry cites the spec
version that resolved it.

## 9. Definition of Done (v1)

- M0–M4 complete (M5 broker may trail)
- Every MUST in §12.1 has a passing, section-named test
- A second machine, following only `docs/deployment.md`, can be brought
  from zero to an SSH-over-Montauk connection
- The Section 8 table above is empty of open entries, each resolved by a
  spec patch or an explicit implementation-defined note
