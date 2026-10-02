# SPDX-License-Identifier: Apache-2.0
"""M5 brokered node: broker | responder | initiator, for the cross-host testbed.

The responder registers with the broker and never binds a public address, so
the initiator can reach its service ONLY through the broker (NAT traversal).
All three derive identical relationship material from a shared --seed.

  broker:     python3 m5_node.py broker --host 0.0.0.0 --port 9000
  responder:  python3 m5_node.py responder --seed <hex> --broker 127.0.0.1:9000
  initiator:  python3 m5_node.py initiator --seed <hex> --broker <broker-ip>:9000
"""

import argparse
import asyncio
import hashlib
import logging
import sys

from montauk import broker, transport
from montauk.core import crypto
from montauk.core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)

ORIGIN_PORT = 8080
ORIGIN_BODY = b"montauk M5: hello through the broker (responder is NAT-blocked)"


def kdf(seed: bytes, label: bytes, n: int = 32) -> bytes:
    return hashlib.sha256(seed + b"|" + label).digest()[:n]


def build(seed_hex: str):
    seed = bytes.fromhex(seed_hex)
    resp_priv = kdf(seed, b"responder-key")
    init_priv = kdf(seed, b"initiator-key")
    broker_priv = kdf(seed, b"broker-key")
    link_psk = kdf(seed, b"broker-psk")
    guest_prior = kdf(seed, b"guest-prior")
    service = ServiceDefinition(kdf(seed, b"service", 16), "web", 0x01, f"127.0.0.1:{ORIGIN_PORT}")
    # Reachability is unused by the brokered path; a placeholder prefix keeps
    # the Relationship valid.
    reach = Reachability(ReachabilityType.DIRECT, prefix=IPv6Prefix.from_string("2001:db8::/64"))
    common = dict(
        prior=kdf(seed, b"prior"),
        handshake_password=kdf(seed, b"password"),
        relationship_id=kdf(seed, b"relid", 16),
        reachability=reach,
        services=(service,),
        created_at=0,
    )
    return resp_priv, init_priv, broker_priv, link_psk, guest_prior, service, common


def _endpoint(broker_pub, link_psk, guest_prior, args):
    """A BrokerEndpoint: rotating rendezvous address if --rendezvous-prefix is
    set, else the fixed --broker host:port."""
    if args.rendezvous_prefix:
        return broker.BrokerEndpoint(
            broker_pub, link_psk,
            prefix=IPv6Prefix.from_string(args.rendezvous_prefix), guest_prior=guest_prior,
        )
    bhost, bport = parse_hostport(args.broker)
    return broker.BrokerEndpoint(broker_pub, link_psk, host=bhost, port=bport)


def parse_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


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


async def run_broker(args) -> int:
    _, _, broker_priv, link_psk, guest_prior, _, _ = build(args.seed)
    if args.rendezvous_prefix:  # bind a rotating computed rendezvous address (§9.2)
        bkr = broker.MontaukBroker(None, None, broker_priv, link_psk,
                                   prefix=IPv6Prefix.from_string(args.rendezvous_prefix),
                                   guest_prior=guest_prior, freebind=True)
    else:
        bkr = broker.MontaukBroker(args.host, args.port, broker_priv, link_psk)
    host, port = await bkr.start()
    print(f"[broker] listening on [{host}]:{port}", flush=True)
    while True:
        await asyncio.sleep(3600)


async def run_responder(args) -> int:
    resp_priv, init_priv, broker_priv, link_psk, guest_prior, service, common = build(args.seed)
    await start_origin()
    identity = Identity.from_private(resp_priv, None)
    rel = Relationship(peer_pubkey=crypto.public_key(init_priv), **common)
    endpoint = _endpoint(crypto.public_key(broker_priv), link_psk, guest_prior, args)
    print(f"[responder] registering with broker ({'rendezvous' if args.rendezvous_prefix else args.broker}); "
          f"origin on 127.0.0.1:{ORIGIN_PORT}", flush=True)
    await broker.serve_brokered_responder(endpoint, identity, rel)
    return 0


async def run_initiator(args) -> int:
    resp_priv, init_priv, broker_priv, link_psk, guest_prior, service, common = build(args.seed)
    identity = Identity.from_private(init_priv, None)
    rel = Relationship(peer_pubkey=crypto.public_key(resp_priv), **common)
    endpoint = _endpoint(crypto.public_key(broker_priv), link_psk, guest_prior, args)
    print(f"[initiator] connecting through broker ({'rendezvous' if args.rendezvous_prefix else args.broker}) ...", flush=True)
    send_cs, recv_cs, reader, writer = await asyncio.wait_for(
        broker.connect_brokered(endpoint, identity, rel, service.service_id), 15
    )
    print("[initiator] bridged + handshake done; sending GET", flush=True)
    await transport.write_frame(writer, send_cs.encrypt(b"", b"GET / HTTP/1.0\r\nHost: montauk\r\n\r\n"))
    body = b""
    while True:
        frame = await asyncio.wait_for(transport.read_frame(reader), 10)
        if frame is None:
            break
        body += recv_cs.decrypt(b"", frame)
    writer.close()
    ok = ORIGIN_BODY in body
    print("[initiator] response:", body.decode(errors="replace"), flush=True)
    print("M5 RESULT:", "PASS" if ok else "FAIL", flush=True)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["broker", "responder", "initiator"])
    ap.add_argument("--seed")
    ap.add_argument("--broker")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--rendezvous-prefix", help="rotating rendezvous mode: broker prefix, e.g. 2001:db8:beef::/64")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="  %(name)s %(levelname)s: %(message)s")
    if args.role == "broker":
        return asyncio.run(run_broker(args))
    if args.role == "responder":
        return asyncio.run(run_responder(args))
    return asyncio.run(run_initiator(args))


if __name__ == "__main__":
    sys.exit(main())
