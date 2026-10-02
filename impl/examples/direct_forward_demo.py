# SPDX-License-Identifier: Apache-2.0
"""M1 demo: an HTTP request forwarded through a live Montauk direct connection.

    uv run python examples/direct_forward_demo.py

Spins up, in one process on IPv6 loopback: an origin HTTP service, a Montauk
responder daemon, and a Montauk client port-forward. Then it makes an HTTP
request through the forward and prints each step. No root required — see the
comment on `bind_host` for the real AnyIP deployment.
"""

import asyncio
import logging
import os
import time

from montauk.client import LocalForward
from montauk.core import crypto, engine
from montauk.core.model import ServiceDefinition
from montauk.daemon import MontaukDaemon
from montauk import pairing


async def start_origin() -> tuple[asyncio.base_events.Server, str]:
    async def handle(reader, writer):
        request = await reader.read(4096)
        line = request.split(b"\r\n", 1)[0].decode(errors="replace")
        body = b"Hello from the origin service! You asked: " + line.encode()
        writer.write(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    return server, f"{host}:{port}"


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="  %(name)s: %(message)s")

    origin_server, origin_target = await start_origin()
    print(f"[1] origin HTTP service listening at {origin_target}")

    service = ServiceDefinition(service_id=os.urandom(16), name="web", internal_target=origin_target)
    alice, alice_rel, bob, bob_rel = pairing.pair(
        crypto.generate_private_key(),
        crypto.generate_private_key(),
        services=(service,),
        bob_prefix="2001:db8:1234:5678::/64",
        alice_prefix="2001:db8:aaaa::/64",
    )
    print("[2] minted a relationship between Alice (initiator) and Bob (responder)")
    address, port = engine.initiator_tuple(alice, alice_rel, service.service_id, int(time.time()))
    print(f"    both sides independently compute the current tuple: [{address}]:{port}")

    # bind_host="::1" / connect_host="::1": rootless loopback mode. For a real
    # deployment, drop both overrides and run once as root:
    #     ip -6 route add local 2001:db8:1234:5678::/64 dev lo
    # so the daemon can bind the computed address directly.
    daemon = MontaukDaemon(bob, [bob_rel], bind_host="::1")
    await daemon.start()
    print("[3] Bob's daemon is listening on the computed ports (window of 3 buckets)")

    forward = LocalForward(alice, alice_rel, service.service_id, connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    print(f"[4] Alice's port-forward is live at {fhost}:{fport}")

    reader, writer = await asyncio.open_connection(fhost, fport)
    writer.write(b"GET /photos HTTP/1.0\r\nHost: montauk\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    print("[5] response received through the encrypted Montauk channel:\n")
    print("    " + response.decode(errors="replace").replace("\r\n", "\n    "))

    await forward.close()
    await daemon.close()
    origin_server.close()
    await origin_server.wait_closed()
    print("[6] done — teardown complete")


if __name__ == "__main__":
    asyncio.run(main())
