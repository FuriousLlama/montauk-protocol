---
title: "Montauk Reference Implementation Roadmap"
status: "Living document"
targets: "montauk_spec.md v0.4.0-draft"
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
| M0 | `impl/` skeleton; crypto + engine + wire as sans-IO modules; golden tests against all §13 vectors; `reference/vectors.json` machine-readable export | Test suite green with zero sockets opened — **done 2026-07-06** (37 tests) |
| M1 | Direct connection end-to-end on one machine (AnyIP on loopback, doc prefix) | Client port-forwards to a local HTTP server through a full Montauk handshake — **done 2026-07-06** (`examples/direct_forward_demo.py`, 2 e2e tests). Rootless loopback mode; real AnyIP address-binding deferred to M3 |
| M2 | Live rotation: listener manager + engine diffs on a real clock | Tuples rotate every 5 min; connection succeeds across a bucket boundary; ±skew within tolerance succeeds, outside fails — **done 2026-07-06** (boundary-timed re-sync loop, `test_rotation.py`, 12 tests) |
| M3 | nftables sync + IPV6_FREEBIND listener; adversarial checks | **done 2026-07-09** — `montauk/firewall.py` (default-drop + timeout set) and freebind listener wired into the daemon (`test_firewall.py`, 56 tests). The adversarial + fail-closed *validation* was done on real hosts in M4 (a more faithful venue than a rootless netns), so no separate netns harness was built |
| M4 | Real deployment across two hosts | **done 2026-07-09** — two Debian VMs on an isolated IPv6 segment (Proxmox testbed, see §10); responder binds real computed addresses via AnyIP+FREEBIND behind an nftables default-drop; initiator independently computes the tuple and gets HTTP through a full handshake; prefix scan sees only silence; daemon crash leaves holes that auto-expire (`harness/m4_node.py`). Deployment write-up: `docs/deployment.md` |
| M5 | Broker: control/data split, match_id flow, bridging | **done 2026-07-09** — `montauk/broker.py` + `harness/m5_node.py`; local integration (`test_broker.py`, 3 tests: HTTP through the bridge, unauthorized + unknown-target rejection) and a **cross-host testbed run** (initiator on 902 reaches a broker-only service on 901; end-to-end handshake through the opaque bridge; PASS). Broker links are plaintext control in M5 — see §8 finding 9 |

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
| 1 | TCP SYN-ACKs before the application sees a byte, so for the *currently valid* tuple, liveness is confirmed at the kernel layer regardless of application silence. The firewall provides silence for invalid tuples; the application provides only reason-indistinguishability on valid ones. | §11.5 should state this nuance explicitly | Closed — v0.4.0-draft §11.5 |
| 2 | Behavior when a service's `internal_target` is down: close after handshake reveals liveness only to an authenticated, authorized peer. Propose: complete handshake, then close silently; never fail before handshake completion. | §7.4 or §8.2 clarification | Closed — v0.4.0-draft §8.2 |
| 3 | (address, port) collisions across streams on one host are cryptographically negligible but possible; the engine should detect and log rather than silently double-book a tuple. | Implementation-defined; possibly a §12 note | Closed — v0.4.0-draft §12.4 |
| 4 | FirstPacket timestamp validity (§11.3, ±30s) and address-bucket validity (§6.4, ±300s) are independent checks with different tolerances; a packet can reach a still-valid listener yet be rejected on timestamp. Now demonstrated by `test_timestamp_skew_tolerance` (skew=±40s reaches the listener, dropped on timestamp). Spec sentence still wanted. | §11.3 note | Closed — v0.4.0-draft §11.3 |
| 5 | IK authenticates the initiator's static key cryptographically, but the spec never says the responder MUST verify that key equals the relationship's `peer_pubkey`. The reference does (and closes silently on mismatch); without it, a party holding a *different* valid relationship's PSK is not bound to a specific identity. Surfaced building M1. | §8.2 should state the responder MUST bind the authenticated static key to the relationship | Closed — v0.4.0-draft §8.2, §12.1 |
| 6 | Graceful connection close / half-close of the proxied stream is undefined. The reference maps TCP FIN through the channel (write_eof each direction); the spec says nothing about how stream end is signaled or whether half-open is allowed. | §8.2 close semantics note | Closed — v0.4.0-draft §8.2 |
| 7 | On IPv6 the AnyIP `local` route is not sufficient to *bind* a computed address — the socket must also set `IPV6_FREEBIND`. Confirmed on real hosts in M4. Route enables delivery; FREEBIND enables bind. | §6.3 / deployment note | Closed — v0.4.0-draft §6.3, §12.1 |
| 8 | The daemon has no signal handler, so `close()` (which deletes the nft table) is not called on SIGTERM/SIGKILL. Crash safety then rests entirely on the per-element timeouts (validated in M4: a killed daemon leaves holes that auto-expire). A graceful `SIGTERM → close()` handler is desirable but not required for safety. | Implementation note | Closed — v0.4.0-draft §12.4; `MontaukDaemon.serve_forever()` SIGTERM cleanup validated on the testbed (nft table deleted on stop, not just expiring) |
| 9 | M5 broker links (client↔broker, initiator↔broker) are plaintext framed control, not Noise-authenticated as spec §8.3 shows. So the broker learns identities from message contents (CONNECT carries the initiator pubkey) and authorization is a soft first-line filter; the real security is the end-to-end handshake through the bridge, which the broker cannot read or replay. Faithful Noise-to-broker links are a v0.x refinement. | §8.3 / §9 — reference deviation to close | Closed — spec v0.4.0-draft §9.3; impl now does Noise-authenticated broker links (`transport.do_broker_link_*`, `BROKER_PROLOGUE`); identities come from the handshake, CONNECT no longer asserts an initiator key; validated cross-host (M5 PASS) |

Add to this table as they surface; every closed entry cites the spec
version that resolved it.

## 9. Definition of Done (v1)

- [x] M0–M5 complete (all milestones, including the broker)
- [x] The Section 8 table above is empty of open entries — all 9 closed
- [x] Direct connection driven by the `montauk` CLI (`pair`/`serve`/`connect`)
      cross-host on the testbed: HTTP 200 through the forward, real computed
      addresses, nft firewall, graceful cleanup
- [x] Every MUST in §12.1 has a passing test — audited line by line (§12 below);
      the one gap (peer-static binding) now has `test_responder_rejects_wrong_peer_identity`
- [x] Brokered reachability wired into the `serve`/`connect` card flow —
      `montauk pair --broker-host` mints brokered cards + a broker card;
      `serve`/`connect` detect the card's broker section and register/forward
      through it (`test_pair_broker_then_brokered_connection`)

## 10. Proxmox Testbed (M4/M5)

A two-node testbed on the `proxmox-staging` host (192.168.150.110), fully
isolated from the LAN. Reproduced from a session; recorded here so it can be
reused or torn down.

**VMs** (Debian 12 genericcloud, cloud-init, uv-managed Python):

| VMID | Name | Segment IP | Role |
| ---- | ---- | ---------- | ---- |
| 901 | montauk-responder | 10.77.0.11 / fd00:6d6f:6e74::11 | AnyIP + nft firewall + daemon + origin |
| 902 | montauk-initiator | 10.77.0.12 / fd00:6d6f:6e74::12 | client port-forward + adversarial probes |

- **Isolated bridge** `vmbr9` (no uplink). Montauk prefix
  `2001:db8:1234:5678::/64` is AnyIP-routed on the responder and routed from
  the initiator via `fd00:6d6f:6e74::11`. Management + WAN (for setup) is
  IPv4 `10.77.0.0/24` on the same bridge.
- **Access**: `ssh -J proxmox-staging -i ~/.ssh/nexus_staging montauk@10.77.0.11`
  (the host is the bastion). Use a **passphrase-less** key — a passphrase-
  protected key fails in BatchMode with the misleading "accepts key then
  permission denied".
- **Run the daemon** as a transient unit so it survives disconnect:
  `sudo systemd-run --unit=montauk-resp --working-directory=<impl> .venv/bin/python harness/m4_node.py responder --seed <hex> --prefix 2001:db8:1234:5678::/64`.
  Do **not** background it with `nohup &` over ssh (SIGHUP kills it), and do
  **not** `pkill -f m4_node.py` (matches your own ssh shell).

**Host changes made for the segment** (reversible; remove when done):

```
ip link add vmbr9 type bridge; ip addr add 10.77.0.1/24 dev vmbr9   # + fd00:...::1/64
sysctl -w net.ipv4.ip_forward=1
nft add table ip montauk_nat ...  # masquerade 10.77.0.0/24 -> eno1
iptables -I FORWARD -s 10.77.0.0/24 -j ACCEPT   # + -d ...  (Docker sets FORWARD policy DROP)
```

**Next**: write `docs/deployment.md` from this, and use the third-node
pattern (add a NAT router VM) for the M5 broker.

## 11. Independent Review (2026-07-09)

An adversarial read-only review (separate agent) of spec v0.4.0-draft vs.
`impl/montauk/`. It confirmed the cryptographic core correct (Noise IKpsk2,
X25519/HKDF/HMAC, address derivation, prologue binding, vectors) and found
bugs concentrated in the I/O shell. All fixed except L8:

| # | Finding | Fix | Status |
| - | ------- | --- | ------ |
| H1 | nftables had no `ct state established,related accept`; a live connection's tuple element expired at the bucket boundary and its inbound path was dropped | Added the established-accept rule (`firewall.py`) | Fixed; validated cross-host (established connection survives element deletion, new connection still dropped) |
| M2 | firewall element timeout tracked the bucket end, not the window end, dropping the trailing half of the ±1-bucket window | `timeout = valid_until + BUCKET_DURATION - now` | Fixed + unit test |
| M3 | no responder-side handshake timeout (§11.6 slowloris) | `asyncio.wait_for(handshake, HANDSHAKE_TIMEOUT=5)` in daemon and brokered responder | Fixed |
| M4 | broker keepalive echo (§7.5.4 MUST) and §9.4 limits unimplemented | keepalive echo + client keepalive sender + dead-client reaper + `MAX_PENDING_MATCHES` | Fixed + keepalive test |
| L5 | broker match/accept race could leave a dial-back awaiting forever | settle `pending.finished` in a `finally` covering the timeout path | Fixed |
| L6 | nonce-cache retention horizon decoupled from validation tolerance | `validate_first_packet` uses `nonce_cache.tolerance` (single source) | Fixed |
| L7 | TCP FIN close is unauthenticated; broker/on-path can truncate undetectably | Spec caveat added (§8.2, §9.5) | Documented |
| — | §6.4 overstated skew tolerance as ±5 min (really ≈±30 s, the timestamp∩address intersection) | Spec corrected (§6.4) | Documented |
| L8 | broker rendezvous is a fixed host:port, not §9.2's computed rotating addresses | `broker.rendezvous_address` + `BrokerEndpoint`; broker binds rotating computed addresses (freebind + rotation) and clients compute the same | Fixed — loopback-validated (`test_brokered_over_rotating_rendezvous_address`); §9.2 corrected to a shared-guest rendezvous (per-party ECDH addresses can't be pre-bound) |

Verdicts: implementation faithful on the crypto/wire core, now faithful on the
firewall/valid-set enforcement and broker keepalives too; protocol design sound.

**Re-review (fresh agent, after the fixes):** confirmed no regressions and that
all six fixes above are correct and complete (crypto re-verified byte-exact
against the vectors). It found five more, now fixed:

| # | Finding | Fix |
| - | ------- | --- |
| MEDIUM-1 | broker's own control-link handshake had no timeout (the one slowloris hole M3 missed) | `wait_for(HANDSHAKE_TIMEOUT)` around `do_broker_link_responder` + first read in `_on_conn` |
| MEDIUM-2 | `save_card` wrote cards (private key, prior, password) world-readable | create + `fchmod` 0600; test asserts the mode |
| LOW-3 | `broker.connect()` indexed `resp[0]` after only a `None` check | guard `if not resp` |
| LOW-4 | §9.4 `MAX_BRIDGES_PER_CLIENT` and `CONNECT_TIMEOUT` unimplemented | per-client bridge counter/cap; `wait_for(CONNECT_TIMEOUT)` in `connect()` |
| LOW-5 | a wedged client holding `_Control.lock` across `drain()` could stall MATCH_OFFERs | bound the control write with `WRITE_TIMEOUT` |

Re-review re-verdict: faithful on everything that matters; design sound;
nothing material outstanding.

**L8 done (after the re-review):** the broker now serves at a rotating computed
rendezvous address (`broker.rendezvous_address`, `BrokerEndpoint`; freebind +
per-bucket rotation, mirroring the daemon), and clients compute the same address
to reach it. §9.2 was corrected to a shared-guest rendezvous keyed from the
semi-public `guest_prior` (the original per-party ECDH address is impractical —
the broker can't pre-bind an address for an initiator whose key it doesn't yet
know). Validated on loopback **and cross-host on the testbed** (broker binds 3
rotating rendezvous addresses in a broker prefix via AnyIP+freebind; the
initiator on the second host computes the same address and connects through it;
M5 PASS). The whole review-and-fix loop is now closed.

**"Finish the reference" (after the review loop):** brokered mode wired into the
CLI card flow (`montauk pair --broker-host` → brokered cards + broker card;
`serve`/`connect` register/forward through the broker — `config.broker_endpoint`,
`broker.brokered_forward`); the §12.1 conformance audit (§12 below) with the
peer-static-binding gap closed; and the L8 rendezvous validated cross-host.

## 12. §12.1 Conformance Audit

Each MUST in spec §12.1 (and the §12.3 interop MUSTs), mapped to a test:

| §12.1 MUST | Test(s) |
| ---------- | ------- |
| X25519 key generation and agreement | `test_13_1_key_generation`, `test_13_2_shared_secret_both_directions` |
| HKDF-SHA256 key derivation | `test_13_3_session_key` |
| HMAC-SHA256 address generation | `test_13_4_address_generation` (+ property test in `test_engine`) |
| Noise_IKpsk2_25519_ChaChaPoly_SHA256 handshake | `test_13_6/13_7_handshake_*`, `test_noise.py` (validated vs. cacophony vector) |
| Noise prologue bound to the First Packet header | `test_4_4_prologue_binding_rejects_restamped_header` |
| Handshake payload length validation | `test_4_4_payload_rules` |
| Length-prefixed message framing | `test_7_1_*` (roundtrip, oversized, chunking-invariant) |
| Timestamp validation with configurable tolerance | `test_11_3_timestamp_window_inclusive`, `test_timestamp_skew_tolerance` |
| Nonce tracking and replay rejection | `test_11_4_nonce_replay_rejected`, `test_11_4_nonce_cache_expires_entries` |
| Address window computation (current ±1 bucket) | `test_6_4_window_is_three_contiguous_buckets`, `test_connection_succeeds_across_boundary` |
| Bind computed addresses without per-address provisioning (FREEBIND) | Behaviorally validated cross-host in M4 and the H1 firewall test; no pure unit test (needs AnyIP/root) |
| Verify handshake-authenticated peer static key vs. relationship | `test_responder_rejects_wrong_peer_identity` |

§12.3 interop MUSTs (big-endian integers, exact constant strings, exact wire
formats, pass all §13 vectors) are covered by `test_golden_vectors.py` +
`test_wire.py`. The one item without a unit test — FREEBIND binding — is
inherently integration-level (it needs a routed prefix + CAP_NET_ADMIN) and is
covered by the M4/H1 testbed runs (§10).
