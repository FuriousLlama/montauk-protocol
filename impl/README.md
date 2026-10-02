# Montauk Reference Implementation

Python reference implementation of the [Montauk Protocol](../montauk_spec.md)
(spec v0.4.0-draft). See [docs/reference_roadmap.md](../docs/reference_roadmap.md)
for architecture, milestones, the spec-feedback log, the independent review,
and the §12.1 conformance audit; see [docs/deployment.md](../docs/deployment.md)
for running it on real hosts.

Current status: **v1 complete (M0–M5)**. Direct connections with live address
rotation, an nftables default-drop firewall synced to the valid set, binding of
computed addresses via AnyIP + `IPV6_FREEBIND`, and a Noise-authenticated broker
for NAT-blocked responders are all implemented and were validated cross-host on
an isolated IPv6 testbed. The sans-IO core (`montauk/core/`) is driven by an
asyncio shell (`transport.py`, `daemon.py`, `client.py`, `broker.py`) that
port-forwards a local socket through a full Montauk handshake to a proxied
service. The daemon re-syncs its listeners and firewall set on every bucket
boundary; connections survive boundary crossings and enforce the ±30s
FirstPacket timestamp window; SIGTERM/SIGINT removes the firewall table.

```
uv sync
uv run pytest                                  # 66 tests: vectors, wire, noise, engine, e2e, rotation, firewall, broker, cli
uv run python examples/direct_forward_demo.py  # watch a request cross the channel
```

## CLI

Direct connection (responder binds real computed addresses in its prefix):

```
uv run montauk keygen                                 # print a new X25519 keypair
uv run montauk pair --responder-prefix 2001:db8:1234:5678::/64 \
    --service ssh=127.0.0.1:22 --out-responder bob.json --out-initiator alice.json
sudo uv run montauk serve bob.json                    # responder (AnyIP + FREEBIND + nft firewall)
uv run montauk connect alice.json ssh -L 127.0.0.1:8022
uv run montauk status bob.json                        # current computed tuples
```

Brokered connection (responder registers with a broker and never binds a
public address):

```
uv run montauk pair --responder-prefix 2001:db8:1234:5678::/64 \
    --service ssh=127.0.0.1:22 --broker-host broker.example:9000 \
    --out-responder bob.json --out-initiator alice.json --out-broker broker.json
uv run montauk broker broker.json                     # or: broker --listen 0.0.0.0:9000 --key <hex> --psk <hex>
uv run montauk serve bob.json                         # registers with the broker; no bind, no root
uv run montauk connect alice.json ssh -L 127.0.0.1:8022
```

`serve` and `connect` detect the broker section in a card and register or
forward through the broker automatically. The CLI runs the broker at a fixed
host:port; the rotating rendezvous address of spec §9.2 is implemented in
`broker.py` (`BrokerEndpoint`, `rendezvous_address`) and covered by tests, but
is not yet wired into the card flow.

`serve` also accepts `--no-firewall` (bind-only enforcement, no nftables) and
`--no-rotate` (no re-sync on bucket boundaries). `pair` accepts
`--initiator-prefix` for relationships where the initiator also acts as a
responder.

For rootless local testing, `serve --bind-host ::1` and `connect --connect-host ::1`
use loopback (computed ports only, no firewall). See
[docs/deployment.md](../docs/deployment.md) for real deployment.

## Layout

- `montauk/core/` — sans-IO protocol logic: `crypto`, `noise`, `engine`
  (address/valid-set), `wire` (framing, FirstPacket, nonce cache), `model`,
  `constants`, `errors`. No sockets, no clock reads, no randomness.
- `montauk/transport.py` — asyncio framing, handshake drivers (direct and
  broker-link), encrypted proxy.
- `montauk/daemon.py` — responder: valid-set → listeners → handshake → proxy;
  freebind listeners, firewall sync, signal-driven cleanup.
- `montauk/client.py` — initiator: local port-forward over Montauk.
- `montauk/firewall.py` — nftables backend (default-drop + per-tuple accept
  with kernel timeouts, so a crashed daemon fails closed) and a null backend.
- `montauk/broker.py` — broker (§9): Noise-authenticated control links,
  match/accept flow, opaque byte bridging, optional rotating rendezvous.
- `montauk/pairing.py`, `montauk/config.py` — relationship minting (§8.1) and
  JSON card (de)serialization.
- `montauk/cli.py` — the `montauk` command.
- `harness/m4_node.py`, `harness/m5_node.py` — cross-host testbed nodes
  (direct and brokered) that derive relationship material from a shared seed;
  see roadmap §10.
- `examples/direct_forward_demo.py` — one-process loopback demo.

## Loopback vs. real deployment

Tests and the demo run rootless by binding `::1` on the computed *port*
(`bind_host` / `connect_host` overrides); the (address, port) tuple is still
computed identically on both sides. For a real deployment the daemon binds
the computed IPv6 address directly — enable AnyIP once as root:

```
ip -6 route add local 2001:db8:1234:5678::/64 dev lo   # or your real prefix/dev
```

then drop the `bind_host`/`connect_host` overrides. Without them, `serve`
binds each computed address with `IPV6_FREEBIND` and installs an nftables
default-drop on the prefix with one accept per currently-valid tuple; each
accept carries a kernel timeout equal to its remaining validity. The route
enables delivery and FREEBIND enables the bind — both are required (§6.3).
