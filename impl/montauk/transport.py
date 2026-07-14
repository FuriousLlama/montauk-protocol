# SPDX-License-Identifier: Apache-2.0
"""Asyncio I/O shell around the sans-IO core.

This is the only layer that touches sockets, the clock, and randomness. It
frames messages (§7.1), drives the handshake (§4.4), and pumps the encrypted
transport in both directions. All protocol decisions live in `core/`.
"""

import asyncio
import os
import time

from .core import crypto, noise, wire
from .core.constants import BROKER_PROLOGUE, MAX_FRAME_BODY, VERSION
from .core.errors import FrameError, HandshakeError
from .core.model import Identity, Relationship, ValidSetEntry

# Noise transport messages are at most 65535 bytes including the 16-byte tag.
MAX_PLAINTEXT = MAX_FRAME_BODY - 16


async def read_frame(reader: asyncio.StreamReader) -> bytes | None:
    """Read one length-prefixed frame body (§7.1). None on clean EOF."""
    try:
        header = await reader.readexactly(2)
    except asyncio.IncompleteReadError:
        return None
    length = int.from_bytes(header, "big")
    if length == 0:
        return b""
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise FrameError("truncated frame body") from exc


async def write_frame(writer: asyncio.StreamWriter, body: bytes) -> None:
    writer.write(wire.encode_frame(body))
    await writer.drain()


def _now() -> int:
    return int(time.time())


async def do_initiator_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    identity: Identity,
    relationship: Relationship,
    service_id: bytes,
    brokered: bool = False,
    now: int | None = None,
    nonce: bytes | None = None,
) -> tuple[noise.CipherState, noise.CipherState]:
    """Send the FirstPacket, complete the IKpsk2 handshake (§8.2), return
    (send, receive) transport cipher states."""
    timestamp = now if now is not None else _now()
    nonce = nonce if nonce is not None else os.urandom(16)
    header = bytes([VERSION]) + timestamp.to_bytes(8, "big") + nonce
    hs = noise.Handshake(
        initiator=True,
        prologue=header,  # §4.4: the 25-byte FirstPacket header is the prologue
        static_private=identity.static_private,
        psk=relationship.handshake_password,
        remote_static=relationship.peer_pubkey,
    )
    payload1 = service_id if brokered else b""
    noise.check_message1_payload(payload1, brokered=brokered)
    m1 = hs.write_message(payload1)
    await write_frame(writer, header + m1)  # == encode_first_packet(...)

    m2 = await read_frame(reader)
    if m2 is None:
        raise HandshakeError("no handshake response")
    payload2 = hs.read_message(m2)
    noise.check_message2_payload(payload2)
    return hs.split()


async def do_responder_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    identity: Identity,
    relationship: Relationship,
    entry: ValidSetEntry | None = None,
    nonce_cache: wire.NonceCache,
    brokered: bool = False,
    now: int | None = None,
) -> tuple[noise.CipherState, noise.CipherState, bytes]:
    """Validate the FirstPacket (§11.3-§11.5), complete the handshake, and
    authenticate the peer. Returns (send, receive, service_id)."""
    now = now if now is not None else _now()
    body = await read_frame(reader)
    if body is None:
        raise HandshakeError("no first packet")
    fp = wire.parse_first_packet(body)
    wire.validate_first_packet(fp, now=now, nonce_cache=nonce_cache)

    hs = noise.Handshake(
        initiator=False,
        prologue=fp.prologue,
        static_private=identity.static_private,
        psk=relationship.handshake_password,
    )
    payload1 = hs.read_message(fp.payload)
    noise.check_message1_payload(payload1, brokered=brokered)
    # Mutual authentication: the static key revealed in message 1 must be the
    # peer this relationship was established with (§1.2).
    if hs.remote_static != relationship.peer_pubkey:
        raise HandshakeError("peer static key mismatch")

    m2 = hs.write_message(b"")
    await write_frame(writer, m2)
    send_cs, recv_cs = hs.split()
    service_id = payload1 if brokered else entry.service_id
    return send_cs, recv_cs, service_id


async def do_broker_link_initiator(reader, writer, *, static_private, remote_static, psk):
    """Authenticated Noise handshake to the broker (party is initiator), so the
    broker learns the party's identity cryptographically (§8.3). Returns the
    (send, recv) cipher states for the encrypted control channel."""
    hs = noise.Handshake(
        initiator=True, prologue=BROKER_PROLOGUE, static_private=static_private, psk=psk, remote_static=remote_static
    )
    await write_frame(writer, hs.write_message(b""))
    m2 = await read_frame(reader)
    if m2 is None:
        raise HandshakeError("no broker link response")
    hs.read_message(m2)
    return hs.split()


async def do_broker_link_responder(reader, writer, *, static_private, psk):
    """Broker side of the link handshake. Returns (send, recv, party_static),
    where party_static is the party's authenticated identity."""
    m1 = await read_frame(reader)
    if m1 is None:
        raise HandshakeError("no broker link hello")
    hs = noise.Handshake(initiator=False, prologue=BROKER_PROLOGUE, static_private=static_private, psk=psk)
    hs.read_message(m1)
    await write_frame(writer, hs.write_message(b""))
    send_cs, recv_cs = hs.split()
    return send_cs, recv_cs, hs.remote_static


async def read_encrypted(reader, recv_cs) -> bytes | None:
    """Read and decrypt one control frame; None on EOF."""
    frame = await read_frame(reader)
    if frame is None:
        return None
    return recv_cs.decrypt(b"", frame)


async def write_encrypted(writer, send_cs, body: bytes) -> None:
    await write_frame(writer, send_cs.encrypt(b"", body))


def _safe_write_eof(writer: asyncio.StreamWriter) -> None:
    try:
        if writer.can_write_eof():
            writer.write_eof()
    except (OSError, RuntimeError):
        pass


async def _plain_to_channel(plain_reader, send_cs, channel_writer):
    try:
        while True:
            data = await plain_reader.read(MAX_PLAINTEXT)
            if not data:
                break
            await write_frame(channel_writer, send_cs.encrypt(b"", data))
    finally:
        _safe_write_eof(channel_writer)


async def _channel_to_plain(channel_reader, recv_cs, plain_writer):
    try:
        while True:
            body = await read_frame(channel_reader)
            if body is None:
                break
            plain_writer.write(recv_cs.decrypt(b"", body))
            await plain_writer.drain()
    finally:
        _safe_write_eof(plain_writer)


async def proxy(
    channel_reader: asyncio.StreamReader,
    channel_writer: asyncio.StreamWriter,
    send_cs: noise.CipherState,
    recv_cs: noise.CipherState,
    plain_reader: asyncio.StreamReader,
    plain_writer: asyncio.StreamWriter,
) -> None:
    """Bidirectionally pipe an encrypted Montauk channel and a plaintext
    socket until both directions reach EOF (§8.2, traffic proxied)."""
    await asyncio.gather(
        _plain_to_channel(plain_reader, send_cs, channel_writer),
        _channel_to_plain(channel_reader, recv_cs, plain_writer),
        return_exceptions=True,
    )
