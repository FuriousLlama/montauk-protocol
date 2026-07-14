# SPDX-License-Identifier: Apache-2.0
"""Command-line interface for the Montauk reference implementation.

    montauk keygen
    montauk pair --responder-prefix <cidr> --service ssh=127.0.0.1:22 \
                 --out-responder bob.json --out-initiator alice.json
    montauk serve bob.json                 # responder daemon (AnyIP + firewall)
    montauk connect alice.json ssh -L 127.0.0.1:8022
    montauk broker --listen 0.0.0.0:9000 --key <hex> --psk <hex>
    montauk status bob.json                # current computed tuples

serve/connect handle direct connections. --bind-host / --connect-host switch to
loopback mode (bind ::1, no firewall) for rootless local testing.
"""

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys

from . import broker as broker_mod
from . import config
from .client import LocalForward
from .core import crypto
from .core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)
from .daemon import MontaukDaemon
from .firewall import NftablesFirewall, NullFirewall

log = logging.getLogger("montauk.cli")


def _split_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


async def _wait_for_signal() -> None:
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, ValueError):
            loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
    await stop


# --- commands ---

def cmd_keygen(args) -> int:
    priv = crypto.generate_private_key()
    print("private:", priv.hex())
    print("public: ", crypto.public_key(priv).hex())
    return 0


def cmd_pair(args) -> int:
    services = []
    for spec in args.service:
        name, _, target = spec.partition("=")
        if not name or not target:
            print(f"bad --service {spec!r}; expected name=host:port", file=sys.stderr)
            return 2
        services.append(ServiceDefinition(os.urandom(16), name, 0x01, target))
    services = tuple(services)

    resp_priv, init_priv = crypto.generate_private_key(), crypto.generate_private_key()
    resp_id = Identity.from_private(resp_priv, IPv6Prefix.from_string(args.responder_prefix))
    init_prefix = IPv6Prefix.from_string(args.initiator_prefix) if args.initiator_prefix else None
    init_id = Identity.from_private(init_priv, init_prefix)

    prior, password, rel_id = os.urandom(32), os.urandom(32), os.urandom(16)
    common = dict(relationship_id=rel_id, prior=prior, handshake_password=password, services=services, created_at=0)
    resp_rel = Relationship(
        peer_pubkey=init_id.static_public,
        reachability=Reachability(ReachabilityType.DIRECT, prefix=init_prefix or resp_id.prefix),
        **common,
    )
    init_rel = Relationship(
        peer_pubkey=resp_id.static_public,
        reachability=Reachability(ReachabilityType.DIRECT, prefix=resp_id.prefix),
        **common,
    )
    config.save_card(args.out_responder, resp_id, [resp_rel])
    config.save_card(args.out_initiator, init_id, [init_rel])
    print(f"wrote responder card {args.out_responder} and initiator card {args.out_initiator}")
    print("services:", ", ".join(f"{s.name}={s.internal_target}" for s in services))
    return 0


async def _serve(args) -> int:
    identity, relationships = config.load_card(args.card)
    if identity.prefix is None:
        print("responder card has no routing prefix", file=sys.stderr)
        return 2
    if args.bind_host:  # loopback/test mode
        daemon = MontaukDaemon(identity, relationships, bind_host=args.bind_host)
    else:  # real deployment
        firewall = NullFirewall() if args.no_firewall else NftablesFirewall(identity.prefix)
        daemon = MontaukDaemon(identity, relationships, freebind=True, firewall=firewall)
    print(f"[serve] {identity.prefix}: {sum(len(r.services) for r in relationships)} service(s)", flush=True)
    await daemon.serve_forever(rotate=not args.no_rotate)
    return 0


async def _connect(args) -> int:
    identity, relationships = config.load_card(args.card)
    rel, svc = config.find_service(relationships, args.service)
    forward = LocalForward(identity, rel, svc.service_id, connect_host=args.connect_host)
    lhost, lport = _split_hostport(args.local)
    host, port = await forward.serve(lhost, lport)
    print(f"[connect] forwarding {host}:{port} -> service {args.service} (peer {rel.peer_pubkey.hex()[:8]})", flush=True)
    try:
        await _wait_for_signal()
    finally:
        await forward.close()
    return 0


async def _broker(args) -> int:
    key = bytes.fromhex(args.key) if args.key else crypto.generate_private_key()
    psk = bytes.fromhex(args.psk) if args.psk else crypto.generate_private_key()
    if not args.key:
        print("broker public:", crypto.public_key(key).hex())
    if not args.psk:
        print("broker link psk:", psk.hex())
    host, port = _split_hostport(args.listen)
    bkr = broker_mod.MontaukBroker(host, port, key, psk)
    bhost, bport = await bkr.start()
    print(f"[broker] listening on {bhost}:{bport}", flush=True)
    try:
        await _wait_for_signal()
    finally:
        await bkr.close()
    return 0


def cmd_status(args) -> int:
    identity, relationships = config.load_card(args.card)
    if identity.prefix is None:
        print("card has no routing prefix (initiator-only card)", file=sys.stderr)
        return 2
    for rel_id, svc_id, addr, port in MontaukDaemon(identity, relationships).current_tuples():
        print(f"rel={rel_id.hex()[:8]} svc={svc_id.hex()[:8]}  [{addr}]:{port}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="montauk", description="Montauk reference implementation CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="print a new X25519 keypair")

    pp = sub.add_parser("pair", help="mint a direct relationship as two cards")
    pp.add_argument("--responder-prefix", required=True, help="responder routing prefix, e.g. 2001:db8::/64")
    pp.add_argument("--initiator-prefix", help="initiator routing prefix (optional)")
    pp.add_argument("--service", action="append", required=True, metavar="name=host:port", help="repeatable")
    pp.add_argument("--out-responder", required=True)
    pp.add_argument("--out-initiator", required=True)

    ps = sub.add_parser("serve", help="run the responder daemon from a card")
    ps.add_argument("card")
    ps.add_argument("--bind-host", help="loopback/test mode: bind this host on computed ports")
    ps.add_argument("--no-firewall", action="store_true", help="skip nftables (bind-only enforcement)")
    ps.add_argument("--no-rotate", action="store_true", help="do not re-sync on bucket boundaries")

    pc = sub.add_parser("connect", help="local port-forward over Montauk")
    pc.add_argument("card")
    pc.add_argument("service")
    pc.add_argument("-L", "--local", required=True, metavar="host:port", help="local listen address")
    pc.add_argument("--connect-host", help="loopback/test mode: connect this host on computed ports")

    pb = sub.add_parser("broker", help="run a broker")
    pb.add_argument("--listen", required=True, metavar="host:port")
    pb.add_argument("--key", help="broker static private key (hex); generated if omitted")
    pb.add_argument("--psk", help="broker link PSK (hex); generated if omitted")

    pst = sub.add_parser("status", help="print current computed tuples for a responder card")
    pst.add_argument("card")
    return p


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="  %(name)s %(levelname)s: %(message)s")
    args = build_parser().parse_args(argv)
    if args.cmd == "keygen":
        return cmd_keygen(args)
    if args.cmd == "pair":
        return cmd_pair(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "serve":
        return asyncio.run(_serve(args))
    if args.cmd == "connect":
        return asyncio.run(_connect(args))
    if args.cmd == "broker":
        return asyncio.run(_broker(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
