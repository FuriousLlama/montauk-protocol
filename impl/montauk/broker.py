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
from .core import crypto, engine, wire
from .core.constants import BROKER_SERVICE_ID, HANDSHAKE_TIMEOUT
from .core.model import IPv6Prefix
from .daemon import _open_listener, split_hostport

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

DIAL_BACK_TIMEOUT = 10  # MATCH_OFFER validity window (§9.4)
KEEPALIVE_INTERVAL = 25  # client sends a keepalive this often (§9.4)
CLIENT_DEAD_AFTER = 75  # no keepalive within this -> reap the registration (§9.4)
MAX_PENDING_MATCHES = 4  # outstanding MATCH_OFFERs per client (§9.4)
MAX_BRIDGES_PER_CLIENT = 8  # concurrent bridges per client (§9.4)
CONNECT_TIMEOUT = 30  # initiator's overall connect budget (§9.4)
WRITE_TIMEOUT = 10  # bound a control-channel write so a wedged reader can't hold the lock


# --- rotating rendezvous address (§9.2) ---

def rendezvous_address(broker_pubkey: bytes, broker_prefix: IPv6Prefix, guest_prior: bytes, T: int):
    """The broker's rotating rendezvous (address, port) for bucket T (§9.2).

    Reference simplification: a single shared guest rendezvous derived from the
    semi-public guest_prior plus the broker's public key and prefix, rather than
    §9.2's per-guest ECDH address (which the broker cannot pre-bind for unknown
    guests). Identity is still established by the Noise link handshake, not the
    address."""
    session_key = crypto.derive_session_key(broker_pubkey, guest_prior)
    return engine.compute_tuple(session_key, broker_pubkey, broker_prefix, BROKER_SERVICE_ID, T)


@dataclass
class BrokerEndpoint:
    """How to reach a broker: either a fixed host:port or a rotating rendezvous
    address computed from the broker's prefix and the shared guest_prior."""

    broker_pubkey: bytes
    link_psk: bytes
    host: str | None = None
    port: int | None = None
    prefix: IPv6Prefix | None = None
    guest_prior: bytes | None = None
    connect_host: str | None = None  # loopback override for the computed address
    clock: object = None

    def resolve(self) -> tuple[str, int]:
        if self.prefix is not None and self.guest_prior is not None:
            now = (self.clock or transport._now)()
            addr, port = rendezvous_address(self.broker_pubkey, self.prefix, self.guest_prior, engine.time_bucket(now))
            return (self.connect_host or str(addr)), port
        return self.host, self.port


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
    pending: int = 0  # outstanding MATCH_OFFERs (§9.4 MAX_PENDING_MATCHES)
    bridges: int = 0  # concurrent bridges (§9.4 MAX_BRIDGES_PER_CLIENT)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def push(self, body: bytes) -> None:
        async with self.lock:  # serialize cipher-state use across concurrent offers/keepalives
            # Bound the write so a wedged (non-reading) client can't hold the lock
            # and block MATCH_OFFERs to other initiators.
            await asyncio.wait_for(transport.write_encrypted(self.writer, self.send_cs, body), WRITE_TIMEOUT)


@dataclass
class _Pending:
    target: bytes
    initiator_reader: asyncio.StreamReader
    initiator_writer: asyncio.StreamWriter
    data: asyncio.Future = field(default_factory=asyncio.Future)
    finished: asyncio.Future = field(default_factory=asyncio.Future)


class MontaukBroker:
    def __init__(self, host, port, static_private, link_psk, *,
                 prefix=None, guest_prior=None, bind_host=None, freebind=False, clock=None, sleep=None):
        self.host, self.port = host, port
        self.static_private = static_private
        self.static_public = crypto.public_key(static_private)
        self.link_psk = link_psk
        self.prefix, self.guest_prior = prefix, guest_prior  # set both -> rotating rendezvous mode
        self.bind_host, self.freebind = bind_host, freebind
        self.clock = clock or transport._now
        self._sleep = sleep or asyncio.sleep
        self._clients: dict[bytes, _Control] = {}
        self._pending: dict[bytes, _Pending] = {}
        self._conns: set[asyncio.Task] = set()
        self._server = None
        self._servers: dict[tuple, object] = {}  # rendezvous mode: (addr, port) -> server
        self._rotation_task: asyncio.Task | None = None

    @property
    def _rendezvous_mode(self) -> bool:
        return self.prefix is not None and self.guest_prior is not None

    def _rendezvous_window(self, now: int) -> dict:
        T = engine.time_bucket(now)
        out = {}
        for delta in (-1, 0, 1):
            addr, port = rendezvous_address(self.static_public, self.prefix, self.guest_prior, T + delta)
            out[(str(addr), port)] = T + delta
        return out

    async def start(self):
        if self._rendezvous_mode:
            await self._sync_rendezvous()
            self._rotation_task = asyncio.create_task(self._rotation_loop())
            addr, port = rendezvous_address(self.static_public, self.prefix, self.guest_prior, engine.time_bucket(self.clock()))
            return str(addr), port
        self._server = await asyncio.start_server(self._on_conn, self.host, self.port)
        return self._server.sockets[0].getsockname()[:2]

    async def _sync_rendezvous(self) -> None:
        want = set(self._rendezvous_window(self.clock()))
        have = set(self._servers)
        for tup in have - want:
            self._servers.pop(tup).close()
        for addr, port in want - have:
            host = self.bind_host or addr
            self._servers[(addr, port)] = await _open_listener(self._on_conn, host, port, freebind=self.freebind)

    async def _rotation_loop(self) -> None:
        while True:
            await self._sleep(engine.next_boundary(self.clock()) - self.clock())
            try:
                await self._sync_rendezvous()
            except Exception:
                log.exception("rendezvous sync failed; retrying next boundary")

    async def close(self) -> None:
        if self._rotation_task is not None:
            self._rotation_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._rotation_task
            self._rotation_task = None
        for task in list(self._conns):
            task.cancel()
        servers = list(self._servers.values()) + ([self._server] if self._server is not None else [])
        for s in servers:
            s.close()
        for s in servers:
            with contextlib.suppress(asyncio.TimeoutError, Exception):
                await asyncio.wait_for(s.wait_closed(), 3)
        self._servers.clear()
        self._server = None

    async def _on_conn(self, reader, writer):
        self._conns.add(asyncio.current_task())
        try:
            # Bound the unauthenticated link handshake and first control message so a
            # stalled connection can't pin a coroutine indefinitely (§11.6 slowloris).
            send_cs, recv_cs, party = await asyncio.wait_for(
                transport.do_broker_link_responder(reader, writer, static_private=self.static_private, psk=self.link_psk),
                HANDSHAKE_TIMEOUT,
            )
            body = await asyncio.wait_for(transport.read_encrypted(reader, recv_cs), HANDSHAKE_TIMEOUT)
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
            while True:  # keep the control channel open, echo keepalives, reap dead clients
                try:
                    frame = await asyncio.wait_for(transport.read_encrypted(reader, recv_cs), CLIENT_DEAD_AFTER)
                except asyncio.TimeoutError:
                    log.info("client %s reaped (no keepalive)", party.hex()[:8])
                    break
                if frame is None:
                    break
                if frame == b"":  # §7.5.4: answer each keepalive with one keepalive
                    await control.push(b"")
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
        if chan.pending >= MAX_PENDING_MATCHES or chan.bridges >= MAX_BRIDGES_PER_CLIENT:  # §9.4 caps
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_TIMEOUT))
            writer.close()
            return
        match_id = os.urandom(16)
        pending = _Pending(target, reader, writer)
        self._pending[match_id] = pending
        chan.pending += 1
        try:
            await chan.push(encode_response(MATCH_OFFER, match_id))
            await transport.write_encrypted(writer, send_cs, encode_response(WAITING))
            data_reader, data_writer, data_send_cs = await asyncio.wait_for(pending.data, DIAL_BACK_TIMEOUT)
            # Both ends present: MATCHED each way (last encrypted frame), then relay raw bytes.
            await transport.write_encrypted(writer, send_cs, encode_response(MATCHED))
            await transport.write_encrypted(data_writer, data_send_cs, encode_response(MATCHED))
            log.info("bridging match %s (target %s)", match_id.hex()[:8], target.hex()[:8])
            chan.bridges += 1
            try:
                await _bridge(reader, writer, data_reader, data_writer)
            finally:
                chan.bridges = max(0, chan.bridges - 1)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                await transport.write_encrypted(writer, send_cs, encode_response(ERROR_TIMEOUT))
        finally:
            # Always settle `finished` so a dial-back that raced past the timeout
            # is not left awaiting forever (L5).
            self._pending.pop(match_id, None)
            chan.pending = max(0, chan.pending - 1)
            if not pending.finished.done():
                pending.finished.set_result(True)
            writer.close()

    async def _handle_accept(self, body, party, reader, writer, send_cs):
        match_id = body[1:17]
        pending = self._pending.get(match_id)
        if pending is None or pending.data.done() or party != pending.target:
            await transport.write_encrypted(writer, send_cs, encode_response(ERROR_NOT_FOUND))
            writer.close()
            return
        pending.data.set_result((reader, writer, send_cs))
        try:
            await pending.finished  # hold the data connection open until the bridge ends
        finally:
            writer.close()


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

async def _open_link(endpoint, static_private):
    host, port = endpoint.resolve()  # fixed host:port or current rotating rendezvous address
    reader, writer = await asyncio.open_connection(host, port)
    send_cs, recv_cs = await transport.do_broker_link_initiator(
        reader, writer, static_private=static_private, remote_static=endpoint.broker_pubkey, psk=endpoint.link_psk
    )
    return reader, writer, send_cs, recv_cs


async def _keepalive_loop(writer, send_cs):
    while True:
        await asyncio.sleep(KEEPALIVE_INTERVAL)
        await transport.write_encrypted(writer, send_cs, b"")  # §7.5.4 keepalive


async def register(endpoint, static_private, client_pubkey, authorizations, on_offer):
    """Register as a client and dispatch each MATCH_OFFER to on_offer(match_id).
    Sends keepalives and blocks holding the control connection until it drops."""
    reader, writer, send_cs, recv_cs = await _open_link(endpoint, static_private)
    await transport.write_encrypted(writer, send_cs, encode_register(client_pubkey, list(authorizations)))
    resp = await transport.read_encrypted(reader, recv_cs)
    if not resp or resp[0] != REGISTERED:
        writer.close()
        raise RuntimeError("broker did not register us")
    keepalive = asyncio.create_task(_keepalive_loop(writer, send_cs))
    try:
        while True:
            frame = await transport.read_encrypted(reader, recv_cs)
            if frame is None:
                break
            if frame and frame[0] == MATCH_OFFER:  # an empty frame is a keepalive echo; ignore
                await on_offer(frame[1:17])
    finally:
        keepalive.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await keepalive
        writer.close()


async def dial_back(endpoint, static_private, match_id):
    """Claim a match with a fresh data connection; returns the raw (reader,
    writer) to run the responder handshake over once MATCHED."""
    reader, writer, send_cs, recv_cs = await _open_link(endpoint, static_private)
    await transport.write_encrypted(writer, send_cs, encode_accept(match_id))
    resp = await transport.read_encrypted(reader, recv_cs)
    if not resp or resp[0] != MATCHED:
        writer.close()
        raise RuntimeError(f"dial-back not matched: {resp!r}")
    return reader, writer  # subsequent bytes are raw end-to-end


async def connect(endpoint, static_private, target_pubkey):
    """Request a target; returns the raw (reader, writer) to run the initiator
    handshake over once MATCHED."""
    reader, writer, send_cs, recv_cs = await _open_link(endpoint, static_private)
    await transport.write_encrypted(writer, send_cs, encode_connect(target_pubkey))

    async def _await_match():
        while True:
            resp = await transport.read_encrypted(reader, recv_cs)
            if not resp:  # None (EOF) or an unexpected empty frame
                raise RuntimeError("broker closed before match")
            if resp[0] == WAITING:
                continue
            if resp[0] == MATCHED:
                return reader, writer  # subsequent bytes are raw end-to-end
            raise BrokerError(resp[0])

    try:
        return await asyncio.wait_for(_await_match(), CONNECT_TIMEOUT)  # §9.4 connect budget
    except asyncio.TimeoutError:
        writer.close()
        raise BrokerError(ERROR_TIMEOUT)
    except Exception:
        writer.close()
        raise


class BrokerError(Exception):
    def __init__(self, code: int):
        self.code = code
        names = {ERROR_UNAUTHORIZED: "unauthorized", ERROR_NOT_FOUND: "not_found", ERROR_TIMEOUT: "timeout"}
        super().__init__(names.get(code, f"error 0x{code:02x}"))


# --- brokered responder / initiator glue (used by tests and the M5 harness) ---

async def _serve_offer(endpoint, match_id, identity, relationship, nonce_cache):
    reader, writer = await dial_back(endpoint, identity.static_private, match_id)
    target_writer = None
    try:
        send_cs, recv_cs, service_id = await asyncio.wait_for(
            transport.do_responder_handshake(
                reader, writer, identity=identity, relationship=relationship, nonce_cache=nonce_cache, brokered=True
            ),
            HANDSHAKE_TIMEOUT,  # §11.6
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


async def serve_brokered_responder(endpoint, identity, relationship):
    """Register and serve brokered connections until cancelled: each MATCH_OFFER
    spawns a dial-back + responder handshake + proxy to the matched service."""
    nonce_cache = wire.NonceCache()

    async def on_offer(match_id):
        asyncio.create_task(_serve_offer(endpoint, match_id, identity, relationship, nonce_cache))

    await register(endpoint, identity.static_private, identity.static_public, [relationship.peer_pubkey], on_offer)


async def connect_brokered(endpoint, identity, relationship, service_id):
    """Initiator: reach the peer through the broker and complete the end-to-end
    handshake over the bridge. Returns (send_cs, recv_cs, reader, writer)."""
    reader, writer = await connect(endpoint, identity.static_private, relationship.peer_pubkey)
    send_cs, recv_cs = await transport.do_initiator_handshake(
        reader, writer, identity=identity, relationship=relationship, service_id=service_id, brokered=True
    )
    return send_cs, recv_cs, reader, writer
