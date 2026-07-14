# SPDX-License-Identifier: Apache-2.0
"""Broker: control/data-split rendezvous for NAT-blocked participants
(spec §7.5, §8.3, §9).

Each party opens a Noise-authenticated link to the broker (§8.3), so the broker
learns its identity cryptographically rather than trusting an asserted value
(§9.3). Control messages (REGISTER / CONNECT / ACCEPT / responses) flow
encrypted over that link. On a match the broker relays **raw bytes** between the
initiator and a responder-dialed data connection; the end-to-end Montauk
handshake runs through that opaque bridge, so the broker cannot read or replay
it (the header is prologue-bound, §4.4).

Once the broker sends MATCHED, both ends stop using the broker-link encryption
and the connection carries raw end-to-end bytes.
"""

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass, field

from . import transport
from .core import wire
from .daemon import split_hostport

log = logging.getLogger("montauk.broker")

# Message type bytes (§7.5)
REGISTER = 0x01
CONNECT = 0x02
ACCEPT = 0x03
REGISTERED = 0x10
WAITING = 0x11
MATCHED = 0x12
MATCH_OFFER = 0x13
ERROR_UNAUTHORIZED = 0x20
ERROR_NOT_FOUND = 0x21
ERROR_TIMEOUT = 0x22

DIAL_BACK_TIMEOUT = 10  # seconds, §9.4


# --- control message bodies (sent encrypted over the broker link) ---

def encode_register(client_pubkey: bytes, authorizations: list[bytes]) -> bytes:
    return bytes([REGISTER]) + client_pubkey + len(authorizations).to_bytes(2, "big") + b"".join(authorizations)


def encode_connect(target_pubkey: bytes) -> bytes:
    return bytes([CONNECT]) + target_pubkey


def encode_accept(match_id: bytes) -> bytes:
    return bytes([ACCEPT]) + match_id


def encode_response(rtype: int, payload: bytes = b"") -> bytes:
    return bytes([rtype]) + payload


@dataclass
class _Control:
    writer: asyncio.StreamWriter
    send_cs: object
    authorized: set[bytes]
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def push(self, body: bytes) -> None:
        async with self.lock:  # serialize cipher-state use across concurrent offers
            await transport.write_encrypted(self.writer, self.send_cs, body)


@dataclass
class _Pending:
    target: bytes
    initiator_reader: asyncio.StreamReader
    initiator_writer: asyncio.StreamWriter
    data: asyncio.Future = field(default_factory=asyncio.Future)
    finished: asyncio.Future = field(default_factory=asyncio.Future)


class MontaukBroker:
    def __init__(self, host: str, port: int, static_private: bytes, link_psk: bytes):
        self.host, self.port = host, port
        self.static_private = static_private
        self.link_psk = link_psk
        self._clients: dict[bytes, _Control] = {}
        self._pending: dict[bytes, _Pending] = {}
        self._conns: set[asyncio.Task] = set()
        self._server = None

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._on_conn, self.host, self.port)
        return self._server.sockets[0].getsockname()[:2]

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for task in list(self._conns):
            task.cancel()
        with contextlib.suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(self._server.wait_closed(), 3)
        self._server = None

    async def _on_conn(self, reader, writer):
        self._conns.add(asyncio.current_task())
        try:
            send_cs, recv_cs, party = await transport.do_broker_link_responder(
                reader, writer, static_private=self.static_private, psk=self.link_psk
            )
            body = await transport.read_encrypted(reader, recv_cs)
            if not body:
                writer.close()
                return
            mtype = body[0]
            if mtype == REGISTER:
                await self._handle_register(body, party, reader, writer, send_cs, recv_cs)
            elif mtype == CONNECT:
                await self._handle_connect(body, party, reader, writer, send_cs, recv_cs)
            elif mtype == ACCEPT:
                await self._handle_accept(body, party, reader, writer, send_cs)
            else:
                writer.close()
        except Exception as exc:
            log.debug("broker connection error: %s", exc)
            writer.close()
        finally:
            self._conns.discard(asyncio.current_task())

    async def _handle_register(self, body, party, reader, writer, send_cs, recv_cs):
        client_pubkey = body[1:33]
        if client_pubkey != party:  # the asserted key must match the authenticated one (§9.3)
            writer.close()
            return
        n = int.from_bytes(body[33:35], "big")
        off = 35
        authorized = {body[off + i * 32 : off + i * 32 + 32] for i in range(n)}
        control = _Control(writer, send_cs, authorized)
        self._clients[party] = control
        await control.push(encode_response(REGISTERED))
        log.info("registered %s (%d authorized)", party.hex()[:8], len(authorized))
        try:
            while True:  # keep control channel open; drain encrypted keepalives
                if await transport.read_encrypted(reader, recv_cs) is None:
                    break
        finally:
            if self._clients.get(party) is control:
                del self._clients[party]
            writer.close()

    async def _handle_connect(self, body, party, reader, writer, send_cs, recv_cs):
        target = body[1:33]
        chan = self._clients.get(target)
        if chan is None:
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_NOT_FOUND))
            writer.close()
            return
        if party not in chan.authorized:  # `party` is the authenticated initiator (§9.3)
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_UNAUTHORIZED))
            writer.close()
            return
        match_id = os.urandom(16)
        pending = _Pending(target, reader, writer)
        self._pending[match_id] = pending
        await chan.push(encode_response(MATCH_OFFER, match_id))
        await transport.write_encrypted(writer, send_cs, encode_response(WAITING))
        try:
            data_reader, data_writer, data_send_cs = await asyncio.wait_for(pending.data, DIAL_BACK_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(match_id, None)
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_TIMEOUT))
            writer.close()
            return
        # Both ends present: send MATCHED (last encrypted frame each way), then
        # relay raw end-to-end bytes.
        await transport.write_encrypted(writer, send_cs, encode_response(MATCHED))
        await transport.write_encrypted(data_writer, data_send_cs, encode_response(MATCHED))
        log.info("bridging match %s (target %s)", match_id.hex()[:8], target.hex()[:8])
        try:
            await _bridge(reader, writer, data_reader, data_writer)
        finally:
            self._pending.pop(match_id, None)
            if not pending.finished.done():
                pending.finished.set_result(True)

    async def _handle_accept(self, body, party, reader, writer, send_cs):
        match_id = body[1:17]
        pending = self._pending.get(match_id)
        if pending is None or pending.data.done() or party != pending.target:
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_NOT_FOUND))
            writer.close()
            return
        pending.data.set_result((reader, writer, send_cs))
        await pending.finished  # hold the data connection open until the bridge ends


async def _bridge(r1, w1, r2, w2):
    """Relay opaque bytes both ways until either side EOFs (§9.4)."""

    async def pipe(src, dst):
        try:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except (OSError, RuntimeError):
                pass

    await asyncio.gather(pipe(r1, w2), pipe(r2, w1), return_exceptions=True)


# --- client-side helpers ---

async def _open_link(broker_host, broker_port, static_private, broker_pubkey, link_psk):
    reader, writer = await asyncio.open_connection(broker_host, broker_port)
    send_cs, recv_cs = await transport.do_broker_link_initiator(
        reader, writer, static_private=static_private, remote_static=broker_pubkey, psk=link_psk
    )
    return reader, writer, send_cs, recv_cs


async def register(broker_host, broker_port, static_private, broker_pubkey, link_psk, client_pubkey, authorizations, on_offer):
    """Register as a client and dispatch each MATCH_OFFER to on_offer(match_id).
    Blocks holding the control connection until it drops."""
    reader, writer, send_cs, recv_cs = await _open_link(broker_host, broker_port, static_private, broker_pubkey, link_psk)
    await transport.write_encrypted(writer, send_cs, encode_register(client_pubkey, list(authorizations)))
    resp = await transport.read_encrypted(reader, recv_cs)
    if not resp or resp[0] != REGISTERED:
        writer.close()
        raise RuntimeError("broker did not register us")
    try:
        while True:
            frame = await transport.read_encrypted(reader, recv_cs)
            if frame is None:
                break
            if frame[0] == MATCH_OFFER:
                await on_offer(frame[1:17])
    finally:
        writer.close()


async def dial_back(broker_host, broker_port, static_private, broker_pubkey, link_psk, match_id):
    """Claim a match with a fresh data connection; returns the raw (reader,
    writer) to run the responder handshake over once MATCHED."""
    reader, writer, send_cs, recv_cs = await _open_link(broker_host, broker_port, static_private, broker_pubkey, link_psk)
    await transport.write_encrypted(writer, send_cs, encode_accept(match_id))
    resp = await transport.read_encrypted(reader, recv_cs)
    if not resp or resp[0] != MATCHED:
        writer.close()
        raise RuntimeError(f"dial-back not matched: {resp!r}")
    return reader, writer  # subsequent bytes are raw end-to-end


async def connect(broker_host, broker_port, static_private, broker_pubkey, link_psk, target_pubkey):
    """Request a target; returns the raw (reader, writer) to run the initiator
    handshake over once MATCHED."""
    reader, writer, send_cs, recv_cs = await _open_link(broker_host, broker_port, static_private, broker_pubkey, link_psk)
    await transport.write_encrypted(writer, send_cs, encode_connect(target_pubkey))
    while True:
        resp = await transport.read_encrypted(reader, recv_cs)
        if resp is None:
            writer.close()
            raise RuntimeError("broker closed before match")
        if resp[0] == WAITING:
            continue
        if resp[0] == MATCHED:
            return reader, writer  # subsequent bytes are raw end-to-end
        writer.close()
        raise BrokerError(resp[0])


class BrokerError(Exception):
    def __init__(self, code: int):
        self.code = code
        names = {ERROR_UNAUTHORIZED: "unauthorized", ERROR_NOT_FOUND: "not_found", ERROR_TIMEOUT: "timeout"}
        super().__init__(names.get(code, f"error 0x{code:02x}"))


# --- brokered responder / initiator glue (used by tests and the M5 harness) ---

async def _serve_offer(broker_host, broker_port, match_id, identity, relationship, nonce_cache, broker_pubkey, link_psk):
    reader, writer = await dial_back(
        broker_host, broker_port, identity.static_private, broker_pubkey, link_psk, match_id
    )
    target_writer = None
    try:
        send_cs, recv_cs, service_id = await transport.do_responder_handshake(
            reader, writer, identity=identity, relationship=relationship, nonce_cache=nonce_cache, brokered=True
        )
        service = relationship.service(service_id)
        host, port = split_hostport(service.internal_target)
        target_reader, target_writer = await asyncio.open_connection(host, port)
    except Exception as exc:
        log.debug("brokered responder handshake failed: %s", exc)
        writer.close()
        return
    log.info("brokered bridge -> %s (%s)", service.internal_target, service.name)
    try:
        await transport.proxy(reader, writer, send_cs, recv_cs, target_reader, target_writer)
    finally:
        writer.close()
        target_writer.close()


async def serve_brokered_responder(broker_host, broker_port, identity, relationship, broker_pubkey, link_psk):
    """Register and serve brokered connections until cancelled: each MATCH_OFFER
    spawns a dial-back + responder handshake + proxy to the matched service."""
    nonce_cache = wire.NonceCache()

    async def on_offer(match_id):
        asyncio.create_task(
            _serve_offer(broker_host, broker_port, match_id, identity, relationship, nonce_cache, broker_pubkey, link_psk)
        )

    await register(
        broker_host, broker_port, identity.static_private, broker_pubkey, link_psk,
        identity.static_public, [relationship.peer_pubkey], on_offer,
    )


async def connect_brokered(broker_host, broker_port, identity, relationship, service_id, broker_pubkey, link_psk):
    """Initiator: reach the peer through the broker and complete the end-to-end
    handshake over the bridge. Returns (send_cs, recv_cs, reader, writer)."""
    reader, writer = await connect(
        broker_host, broker_port, identity.static_private, broker_pubkey, link_psk, relationship.peer_pubkey
    )
    send_cs, recv_cs = await transport.do_initiator_handshake(
        reader, writer, identity=identity, relationship=relationship, service_id=service_id, brokered=True
    )
    return send_cs, recv_cs, reader, writer
