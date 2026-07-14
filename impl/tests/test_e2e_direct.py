# SPDX-License-Identifier: Apache-2.0
"""M1 acceptance: an HTTP request port-forwarded through a full Montauk direct
connection (compute tuple -> connect -> FirstPacket -> IKpsk2 handshake ->
service identified by tuple -> proxy).

Runs entirely on IPv6 loopback (bind/connect "::1", computed ports), so it
needs no root and no AnyIP route. The (address, port) tuple is still computed
identically on both sides; only the socket bind uses ::1 instead of the
computed address.
"""

import asyncio
import dataclasses

from conftest import ORIGIN_BODY, http_get, make_relationship, start_origin

from montauk.client import LocalForward
from montauk.daemon import MontaukDaemon


async def _scenario() -> bytes:
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)

    daemon = MontaukDaemon(bob, [bob_rel], bind_host="::1")
    await daemon.start()
    forward = LocalForward(alice, alice_rel, service.service_id, connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    try:
        return await http_get(fhost, fport)
    finally:
        await forward.close()
        await daemon.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_e2e_direct_forward():
    response = asyncio.run(asyncio.wait_for(_scenario(), timeout=15))
    assert b"200 OK" in response
    assert ORIGIN_BODY in response


async def _wrong_password_scenario() -> bytes:
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)
    alice_rel = dataclasses.replace(alice_rel, handshake_password=bytes(32))  # wrong PSK

    daemon = MontaukDaemon(bob, [bob_rel], bind_host="::1")
    await daemon.start()
    forward = LocalForward(alice, alice_rel, service.service_id, connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    try:
        return await http_get(fhost, fport)
    finally:
        await forward.close()
        await daemon.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_e2e_wrong_password_gets_nothing():
    """A client without the correct handshake_password never reaches the service."""
    response = asyncio.run(asyncio.wait_for(_wrong_password_scenario(), timeout=15))
    assert response == b""
