# SPDX-License-Identifier: Apache-2.0
"""M5: brokered connection end to end (spec §8.3, §9).

Broker + responder + initiator in one process over loopback. The broker only
relays opaque bytes; the end-to-end Montauk handshake runs through the bridge.
"""

import asyncio
import dataclasses

import pytest

from conftest import ORIGIN_BODY, make_relationship, start_origin

from montauk import broker, pairing, transport
from montauk.core import crypto
from montauk.core.model import Identity


async def _recv_all(reader, recv_cs, timeout=10) -> bytes:
    out = b""
    while True:
        frame = await asyncio.wait_for(transport.read_frame(reader), timeout)
        if frame is None:
            break
        out += recv_cs.decrypt(b"", frame)
    return out


async def _brokered_http_scenario():
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)

    bkr = broker.MontaukBroker("127.0.0.1", 0)
    bhost, bport = await bkr.start()
    responder = asyncio.create_task(broker.serve_brokered_responder(bhost, bport, bob, bob_rel))
    await asyncio.sleep(0.3)  # let the responder register

    try:
        send_cs, recv_cs, reader, writer = await asyncio.wait_for(
            broker.connect_brokered(bhost, bport, alice, alice_rel, service.service_id), 10
        )
        await transport.write_frame(writer, send_cs.encrypt(b"", b"GET / HTTP/1.0\r\nHost: montauk\r\n\r\n"))
        body = await _recv_all(reader, recv_cs)
        writer.close()
        return body
    finally:
        responder.cancel()
        await asyncio.gather(responder, return_exceptions=True)
        await bkr.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_brokered_http_end_to_end():
    body = asyncio.run(asyncio.wait_for(_brokered_http_scenario(), 20))
    assert b"200 OK" in body
    assert ORIGIN_BODY in body


async def _unauthorized_scenario():
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)
    # A stranger with its own key, not in bob's authorized list.
    eve = Identity.from_private(crypto.generate_private_key(), None)
    eve_rel = dataclasses.replace(alice_rel, peer_pubkey=bob.static_public)

    bkr = broker.MontaukBroker("127.0.0.1", 0)
    bhost, bport = await bkr.start()
    responder = asyncio.create_task(broker.serve_brokered_responder(bhost, bport, bob, bob_rel))
    await asyncio.sleep(0.3)
    try:
        try:
            await asyncio.wait_for(broker.connect_brokered(bhost, bport, eve, eve_rel, service.service_id), 10)
            return "connected"  # should not happen
        except broker.BrokerError as exc:
            return exc.args[0]
    finally:
        responder.cancel()
        await asyncio.gather(responder, return_exceptions=True)
        await bkr.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_broker_rejects_unauthorized_initiator():
    result = asyncio.run(asyncio.wait_for(_unauthorized_scenario(), 20))
    assert result == "unauthorized"


async def _unknown_target_scenario():
    bkr = broker.MontaukBroker("127.0.0.1", 0)
    bhost, bport = await bkr.start()
    alice = Identity.from_private(crypto.generate_private_key(), None)
    unknown = crypto.generate_private_key()
    try:
        try:
            await asyncio.wait_for(
                broker.connect(bhost, bport, crypto.public_key(unknown), alice.static_public), 10
            )
            return "connected"
        except broker.BrokerError as exc:
            return exc.args[0]
    finally:
        await bkr.close()


def test_broker_unknown_target_not_found():
    assert asyncio.run(asyncio.wait_for(_unknown_target_scenario(), 20)) == "not_found"
