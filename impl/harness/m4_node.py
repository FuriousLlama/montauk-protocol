# SPDX-License-Identifier: Apache-2.0
"""M4 cross-host node: run one end of a real Montauk connection between two hosts.

Both hosts derive identical relationship material from a shared --seed, so no
private keys are exchanged. The responder binds real computed IPv6 addresses in
its routing prefix (AnyIP + IPV6_FREEBIND) behind an nftables default-drop; the
initiator port-forwards to it and probes the prefix adversarially.

  responder:  sudo python3 m4_node.py responder --seed <hex> --prefix <cidr>
  initiator:  python3 m4_node.py initiator --seed <hex> --prefix <cidr>

Route/AnyIP setup is done by the orchestrator (needs root); this script is the
protocol. The responder also serves a trivial HTTP origin on 127.0.0.1:8080.
"""

import argparse
import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import sys
import time

from montauk.client import LocalForward
from montauk.core import crypto, engine
from montauk.core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)
from montauk.daemon import MontaukDaemon
from montauk.firewall import NftablesFirewall

ORIGIN_PORT = 8080
ORIGIN_BODY = b"montauk cross-host M4: hello from the responder origin"


def kdf(seed: bytes, label: bytes, n: int = 32) -> bytes:
    return hashlib.sha256(seed + b"|" + label).digest()[:n]


def build(seed_hex: str, prefix_str: str):
    """Derive the shared relationship from the seed (identical on both hosts)."""
    seed = bytes.fromhex(seed_hex)
    prefix = IPv6Prefix.from_string(prefix_str)
    resp_priv = kdf(seed, b"responder-key")
    init_priv = kdf(seed, b"initiator-key")
    service = ServiceDefinition(kdf(seed, b"service", 16), "web", 0x01, f"127.0.0.1:{ORIGIN_PORT}")
    common = dict(
        prior=kdf(seed, b"prior"),
        handshake_password=kdf(seed, b"password"),
        relationship_id=kdf(seed, b"relid", 16),
        reachability=Reachability(ReachabilityType.DIRECT, prefix=prefix),
        services=(service,),
        created_at=0,
    )
    return prefix, resp_priv, init_priv, service, common


async def start_origin() -> None:
    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(ORIGIN_BODY), ORIGIN_BODY)
        )
        await writer.drain()
        writer.close()

    await asyncio.start_server(handle, "127.0.0.1", ORIGIN_PORT)


async def run_responder(args) -> int:
    prefix, resp_priv, init_priv, service, common = build(args.seed, args.prefix)
    await start_origin()  # internal_target already points here
    identity = Identity.from_private(resp_priv, prefix)
    rel = Relationship(peer_pubkey=crypto.public_key(init_priv), **common)
    daemon = MontaukDaemon(identity, [rel], freebind=True, firewall=NftablesFirewall(prefix))
    await daemon.start()
    tuples = [f"[{a}]:{p}" for _, _, a, p in daemon.current_tuples()]
    print(f"[responder] daemon up on {prefix}; live tuples: {tuples}", flush=True)
    while True:
        await asyncio.sleep(3600)


async def _connect_state(host: str, port: int, timeout: float) -> str:
    """'open' | 'timeout' | 'refused' for a bare TCP connect."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except (ConnectionRefusedError, OSError):
        return "refused"


async def run_initiator(args) -> int:
    prefix, resp_priv, init_priv, service, common = build(args.seed, args.prefix)
    identity = Identity.from_private(init_priv, None)
    rel = Relationship(peer_pubkey=crypto.public_key(resp_priv), **common)
    results: dict[str, object] = {}

    addr, port = engine.initiator_tuple(identity, rel, service.service_id, int(time.time()))
    print(f"[initiator] computed current tuple: [{addr}]:{port}", flush=True)

    # 1. Legit forward: real computed address, full handshake, proxied origin.
    print("[initiator] phase 1: legit port-forward + HTTP GET ...", flush=True)
    forward = LocalForward(identity, rel, service.service_id)
    lhost, lport = await forward.serve("127.0.0.1", 0)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(lhost, lport), 10)
        writer.write(b"GET / HTTP/1.0\r\nHost: montauk\r\n\r\n")
        await writer.drain()
        body = await asyncio.wait_for(reader.read(), 15)
        writer.close()
        results["legit_forward"] = ORIGIN_BODY in body
    except Exception as exc:
        results["legit_forward"] = False
        print(f"[initiator] legit forward error: {exc!r}", flush=True)
    finally:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(forward.close(), 5)  # don't hang on a stuck handler

    # 2. Positive control: the current valid tuple accepts a bare TCP connect.
    print("[initiator] phase 2: bare TCP connect to the valid tuple ...", flush=True)
    results["valid_tuple_tcp"] = await _connect_state(str(addr), port, 4) == "open"

    # 3. Adversarial: non-valid addresses/ports in the prefix must be silently
    #    dropped (timeout), never refused with a RST (§11.5).
    print("[initiator] phase 3: adversarial scan of non-valid tuples ...", flush=True)
    base = int(ipaddress.IPv6Network(args.prefix).network_address)
    probes = []
    for i in range(6):
        scan_addr = ipaddress.IPv6Address(base + 0xDEAD0000 + i * 7919)
        probes.append(await _connect_state(str(scan_addr), 20000 + i * 111, 3))
    results["scan_states"] = probes
    results["scan_all_silent"] = all(state == "timeout" for state in probes)

    ok = bool(results["legit_forward"]) and bool(results["valid_tuple_tcp"]) and bool(results["scan_all_silent"])
    print("[initiator] RESULTS:", flush=True)
    for k, v in results.items():
        print(f"  {k}: {v}", flush=True)
    print("M4 RESULT:", "PASS" if ok else "FAIL", flush=True)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["responder", "initiator"])
    ap.add_argument("--seed", required=True)
    ap.add_argument("--prefix", required=True)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="  %(name)s %(levelname)s: %(message)s")
    if args.role == "responder":
        return asyncio.run(run_responder(args))
    return asyncio.run(run_initiator(args))


if __name__ == "__main__":
    sys.exit(main())
