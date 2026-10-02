# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import os
import pathlib

import pytest

from montauk import pairing
from montauk.core import crypto
from montauk.core.model import ServiceDefinition

VECTORS_PATH = pathlib.Path(__file__).resolve().parents[2] / "reference" / "vectors.json"

ORIGIN_BODY = b"hello from the origin service"


@pytest.fixture(scope="session")
def vectors():
    """All spec §13 vectors, loaded from the machine-readable export."""
    return json.loads(VECTORS_PATH.read_text())["vectors"]


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


# --- shared end-to-end helpers (loopback, rootless) ---

async def start_origin(body: bytes = ORIGIN_BODY):
    """A trivial HTTP/1.0 origin that answers once per connection and closes."""

    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    return server, f"{host}:{port}"


async def http_get(host: str, port: int, request: bytes = b"GET / HTTP/1.0\r\nHost: montauk\r\n\r\n") -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(request)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


def make_relationship(origin_target: str):
    """Mint a fresh Alice(initiator)/Bob(responder) relationship for one service."""
    service = ServiceDefinition(service_id=os.urandom(16), name="web", internal_target=origin_target)
    alice, alice_rel, bob, bob_rel = pairing.pair(
        crypto.generate_private_key(),
        crypto.generate_private_key(),
        services=(service,),
        bob_prefix="2001:db8:1234:5678::/64",
        alice_prefix="2001:db8:aaaa::/64",
    )
    return service, alice, alice_rel, bob, bob_rel
