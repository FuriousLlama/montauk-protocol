---
title: "Montauk Deployment Guide"
status: "Living document"
targets: "montauk_spec.md v0.4.0-draft; impl reference implementation"
date: "2026-07-09"
---

# Deploying Montauk

This guide deploys a **direct** Montauk connection between two hosts: a
*responder* that offers a service and an *initiator* that reaches it by
computed address. It was written from the M4 testbed
([reference_roadmap.md](reference_roadmap.md) §10). Brokered/NAT deployment
is covered at the end once M5 lands.

## 1. What you need

- **Responder**: a host with a **routed IPv6 prefix** delegated to it (a
  `/64` is ideal), and `CAP_NET_ADMIN` (root, `sudo`, a systemd unit with
  `AmbientCapabilities=CAP_NET_ADMIN`, or a `setcap`'d interpreter).
- **Initiator**: any host with IPv6 connectivity and a route to the
  responder's prefix.
- Both: Python 3.12+ (this guide uses [uv](https://astral.sh/uv) to manage
  it), and `nftables` on the responder.

A "routed prefix" means packets to any address in the prefix are delivered to
the responder host. That is the deployment the protocol is designed for
(spec §6.3). The on-link-LAN alternative needs ND proxying and is not covered
here.

## 2. Establish the relationship (out of band)

Both parties need the same relationship material — public keys, Prior,
handshake password, the responder's prefix, and the service definitions —
exchanged over a secure out-of-band channel (spec §8.1). Each party persists
its half as a **card** (JSON). To bootstrap a matched pair:

```
montauk pair --responder-prefix 2001:db8:1234:5678::/64 \
             --service ssh=127.0.0.1:22 \
             --out-responder bob.json --out-initiator alice.json
```

`bob.json` goes to the responder host, `alice.json` to the initiator. In a real
deployment you would generate each identity locally (`montauk keygen`) and
exchange only public material out of band; `pair` is the convenience path.

## 3. Responder

**a. Route the prefix locally (AnyIP).** Let the host accept the whole prefix
as local so the daemon can bind any address in it:

```
sudo ip -6 route add local 2001:db8:1234:5678::/64 dev eth0
```

**b. Run the daemon.** It binds the rotating computed addresses (with
`IPV6_FREEBIND`) and installs the nftables firewall itself. Run it as a
**systemd unit** so it survives your session and cleans up on stop — do *not*
`nohup … &` over ssh (SIGHUP kills it):

```
sudo systemd-run --unit=montauk-responder \
  --working-directory=/opt/montauk/impl \
  /opt/montauk/impl/.venv/bin/montauk serve /etc/montauk/bob.json
```

On `systemctl stop`, the daemon catches SIGTERM and removes its firewall table
and listeners; a crash instead relies on the per-tuple timeouts to expire the
holes (both fail closed). The daemon:

- binds `current ±1` bucket tuples (3 listeners), rotating every 5 minutes;
- installs `table ip6 montauk` with a default-drop on the prefix and an
  accept for exactly the currently-valid `(address, port)` tuples, each with
  a timeout equal to its remaining validity.

**c. Verify.**

```
sudo ss -Hltn | grep 2001:db8            # 3 listeners on computed addresses
sudo nft list set ip6 montauk valid      # 3 elements, counting down
```

## 4. Initiator

**a. Route to the prefix** (only if it is not already on-link — e.g. across a
segment where the responder is the next hop):

```
sudo ip -6 route add 2001:db8:1234:5678::/64 via <responder-address> dev eth0
```

**b. Run the port-forward** (`ssh -L` model): each local connection triggers
a fresh Montauk connection to the peer's current computed tuple.

```
montauk connect alice.json ssh -L 127.0.0.1:8022
ssh -p 8022 127.0.0.1        # e.g. SSH over Montauk
```

`montauk status bob.json` on the responder prints the currently-valid tuples if
you want to confirm both sides agree.

## 5. What you should observe

- The initiator and responder **independently compute the same address**;
  the connection completes a full Noise IKpsk2 handshake and proxies to the
  service.
- A scan of any *other* address in the prefix gets **no response at all**
  (the firewall drops the SYN; no RST) — validated in M4.
- If the daemon crashes, its firewall holes **auto-expire** via the nft
  timeouts — nothing is left scannable (validated in M4).

## 6. Gotchas (learned the hard way in M4)

- **`IPV6_FREEBIND` is required to bind**, in addition to the AnyIP route.
  The route makes the address *deliverable*; FREEBIND lets the socket *bind*
  an address not explicitly assigned. The reference sets it automatically.
- **Host packet forwarding / Docker.** If the responder (or a router in
  front of it) runs Docker, the iptables `FORWARD` policy is `DROP`; forwarded
  Montauk traffic needs an explicit `ACCEPT`. Not an issue when the responder
  is the final destination, but it bit the M4 NAT gateway.
- **Detach with systemd, not `nohup`.** Over ssh, `nohup … & disown` did not
  survive; a transient systemd unit did.
- **Use a passphrase-less key for automation.** A passphrase-protected ssh
  key fails in `BatchMode` with the misleading "server accepts key … then
  Permission denied" — the key is offered but cannot be *signed* with.

## 7. Security operations

- **Silent rejection** (spec §11.5): the firewall drops invalid tuples with
  no response. Nuance (roadmap §8 finding 1): for the *currently valid* tuple
  the kernel completes the TCP handshake before the application sees a byte,
  so liveness of a valid endpoint is confirmed at the TCP layer — finding it
  already requires the secret.
- **Graceful shutdown**: the daemon deletes its nft table on clean
  `close()`. On a crash, rely on the per-element timeouts. A
  `SIGTERM → close()` handler is a recommended add (roadmap §8 finding 8).
- **Clock sync**: both hosts need loosely synchronized clocks (±30s for the
  timestamp check, ±300s for the address window). Run NTP.

## 8. Brokered / NAT deployment

For participants behind NAT, a broker bridges connections without being able
to decrypt them (spec §9). Run a broker on a reachable third host:

```
montauk broker --listen 0.0.0.0:9000 --key <hex> --psk <hex>
```

Clients open Noise-authenticated links to the broker; an initiator's request is
matched to a registered responder, which dials back a data connection, and the
broker relays raw bytes while the end-to-end handshake runs through the bridge.
The brokered client/initiator flow is exercised by `harness/m5_node.py` and
validated cross-host (roadmap §10); wiring brokered reachability into the
`serve`/`connect` card flow is the remaining CLI step.
