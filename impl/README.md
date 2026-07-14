# Montauk Reference Implementation

Python reference implementation of the [Montauk Protocol](../montauk_spec.md).
See [docs/reference_roadmap.md](../docs/reference_roadmap.md) for architecture
and milestones.

Current status: **M2** — direct connection end to end, with live address
rotation. The sans-IO core (`montauk/core/`) is driven by an asyncio shell
(`transport.py`, `daemon.py`, `client.py`) that port-forwards a local socket
through a full Montauk handshake to a proxied service. The daemon re-syncs its
listeners on every bucket boundary; connections survive boundary crossings and
enforce the ±30s FirstPacket timestamp window.

```
uv sync
uv run pytest                                  # 51 tests: vectors, core, e2e, rotation
uv run python examples/direct_forward_demo.py  # watch a request cross the channel
```

## Layout

- `montauk/core/` — sans-IO protocol logic: `crypto`, `noise`, `engine`
  (address/valid-set), `wire` (framing, FirstPacket, nonce cache), `model`.
  No sockets, no clock reads, no randomness.
- `montauk/transport.py` — asyncio framing, handshake drivers, encrypted proxy.
- `montauk/daemon.py` — responder: valid-set → listeners → handshake → proxy.
- `montauk/client.py` — initiator: local port-forward over Montauk.
- `montauk/pairing.py` — mint a relationship between two parties (§8.1).

## Loopback vs. real deployment

Tests and the demo run rootless by binding `::1` on the computed *port*
(`bind_host` / `connect_host` overrides); the (address, port) tuple is still
computed identically on both sides. For a real deployment the daemon binds
the computed IPv6 address directly — enable AnyIP once as root:

```
ip -6 route add local 2001:db8:1234:5678::/64 dev lo   # or your real prefix/dev
```

then drop the `bind_host`/`connect_host` overrides. Real address-binding lands
as a tested path in M3.
