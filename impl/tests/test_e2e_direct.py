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

from montauk import transport
from montauk.client import LocalForward
from montauk.core import crypto, wire
from montauk.core.model import Identity
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


async def _peer_static_mismatch_scenario() -> str:
    service, alice, alice_rel, bob, bob_rel = make_relationship("127.0.0.1:9")
    eve = Identity.from_private(crypto.generate_private_key(), None)  # right PSK, wrong identity
    eve_rel = dataclasses.replace(alice_rel)  # same prior/password, peer=bob
    result = {}

    async def handle(reader, writer):
        try:
            await transport.do_responder_handshake(
                reader, writer, identity=bob, relationship=bob_rel, nonce_cache=wire.NonceCache(), brokered=True
            )
            result["r"] = "accepted"
        except Exception as exc:
            result["r"] = str(exc)
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = srv.sockets[0].getsockname()[:2]
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await transport.do_initiator_handshake(
            reader, writer, identity=eve, relationship=eve_rel, service_id=service.service_id, brokered=True
        )
    except Exception:
        pass
    writer.close()
    await asyncio.sleep(0.3)
    srv.close()
    await srv.wait_closed()
    return result.get("r", "")


def test_responder_rejects_wrong_peer_identity():
    """§8.2/§12.1: the responder MUST reject an initiator whose handshake-
    authenticated static key is not the relationship's peer_pubkey, even with
    the correct PSK (the address already binds identity; this is defense in depth)."""
    r = asyncio.run(asyncio.wait_for(_peer_static_mismatch_scenario(), 10))
    assert "peer static" in r.lower(), r
