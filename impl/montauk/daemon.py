# SPDX-License-Identifier: Apache-2.0
"""Responder daemon: binds computed addresses, handshakes, proxies to services.

The valid set (§6.4) drives one listener per (relationship, service, bucket)
tuple. In real deployment each listener binds the computed IPv6 address via
AnyIP (`ip -6 route add local <prefix> dev <dev>`); `bind_host` overrides that
with a single address (e.g. "::1") for rootless local testing, where only the
computed port is used.
"""

import asyncio
import contextlib
import logging
import socket

from . import transport
from .core import engine, wire
from .core.model import Identity, ValidSetEntry
from .firewall import Firewall, NullFirewall

log = logging.getLogger("montauk.daemon")

IPV6_FREEBIND = getattr(socket, "IPV6_FREEBIND", 78)


def split_hostport(target: str) -> tuple[str, int]:
    """Parse an internal_target "host:port", accepting [v6]:port form."""
    if target.startswith("["):
        host, _, port = target[1:].partition("]:")
    else:
        host, _, port = target.rpartition(":")
    return host, int(port)


async def _open_listener(handler, host: str, port: int, *, freebind: bool):
    """Start a TCP listener. With freebind=True the socket sets IPV6_FREEBIND so
    it can bind a computed address that is not (yet) assigned to an interface —
    the real-deployment case, where an AnyIP route makes the prefix deliverable
    (§6.3). Without it, asyncio binds host:port directly (loopback tests)."""
    if not freebind:
        return await asyncio.start_server(handler, host, port)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, IPV6_FREEBIND, 1)
    sock.bind((host, port))
    sock.setblocking(False)
    return await asyncio.start_server(handler, sock=sock)


class MontaukDaemon:
    def __init__(
        self,
        identity: Identity,
        relationships,
        *,
        clock=None,
        sleep=None,
        bind_host: str | None = None,
        freebind: bool = False,
        firewall: Firewall | None = None,
    ):
        if identity.prefix is None:
            raise ValueError("responder identity requires a routing prefix")
        self.identity = identity
        self.relationships = {r.relationship_id: r for r in relationships}
        self.clock = clock or transport._now
        self._sleep = sleep or asyncio.sleep
        self.bind_host = bind_host
        self.freebind = freebind
        self.firewall = firewall or NullFirewall()
        self._servers: dict[ValidSetEntry, asyncio.base_events.Server] = {}
        self._nonce_cache = wire.NonceCache()
        self._rotation_task: asyncio.Task | None = None
        self._sync_count = 0

    async def start(self, *, rotate: bool = True) -> None:
        """Bind the current valid set. With rotate=True (default), also run a
        background task that re-syncs on every bucket boundary."""
        await self.firewall.start()
        await self.sync()
        self._rotation_task = asyncio.create_task(self._rotation_loop()) if rotate else None

    def _delay_until_next_sync(self, now: int) -> int:
        """Seconds to sleep before the next re-sync (always 1..BUCKET_DURATION)."""
        return engine.next_boundary(now) - now

    async def _rotation_loop(self) -> None:
        while True:
            await self._sleep(self._delay_until_next_sync(self.clock()))
            try:
                await self.sync()
            except Exception:  # a transient bind failure must not kill rotation
                log.exception("valid-set sync failed; retrying next boundary")

    async def sync(self) -> None:
        """Bring listeners in line with the valid set at the current time.
        Idempotent: closing a rotated-out server stops new accepts but lets
        in-flight connections continue (§8.4)."""
        now = self.clock()
        want = engine.responder_valid_set(self.identity, self.relationships.values(), now)
        added, removed = engine.diff(frozenset(self._servers), want)
        # Close firewall holes before their listeners; open them only after the
        # new listeners are bound. Invariant: a hole is open only while a socket
        # is accepting behind it, so a scanner never elicits a RST (§11.5).
        await self.firewall.revoke(removed)
        for entry in removed:
            self._servers.pop(entry).close()
        for entry in added:
            host = self.bind_host or str(entry.address)
            server = await _open_listener(self._make_handler(entry), host, entry.port, freebind=self.freebind)
            self._servers[entry] = server
            log.info(
                "listening [%s]:%d  rel=%s svc=%s (computed %s)",
                host, entry.port, entry.relationship_id.hex()[:8], entry.service_id.hex()[:8], entry.address,
            )
        await self.firewall.allow(added, now)
        self._sync_count += 1

    def listening_ports(self) -> set[int]:
        """Ports currently bound — the sliding address window (§6.4)."""
        return {e.port for e in self._servers}

    def _make_handler(self, entry: ValidSetEntry):
        async def handler(reader, writer):
            await self._handle(entry, reader, writer)

        return handler

    def _drop(self, peer, reason: str) -> None:
        """The single silent-drop funnel (§11.5): log locally, never respond."""
        log.debug("drop from %s: %s", peer, reason)

    async def _handle(self, entry: ValidSetEntry, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        target_writer = None
        try:
            relationship = self.relationships[entry.relationship_id]
            send_cs, recv_cs, service_id = await transport.do_responder_handshake(
                reader, writer,
                identity=self.identity,
                relationship=relationship,
                entry=entry,
                nonce_cache=self._nonce_cache,
                now=self.clock(),
            )
            service = relationship.service(service_id)
            host, port = split_hostport(service.internal_target)
            target_reader, target_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            self._drop(peer, str(exc))
            writer.close()
            return

        log.info("bridged %s -> %s (%s)", peer, service.internal_target, service.name)
        try:
            await transport.proxy(reader, writer, send_cs, recv_cs, target_reader, target_writer)
        finally:
            writer.close()
            target_writer.close()

    async def close(self) -> None:
        if self._rotation_task is not None:
            self._rotation_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._rotation_task
            self._rotation_task = None
        for server in self._servers.values():
            server.close()
        await asyncio.gather(*(s.wait_closed() for s in self._servers.values()), return_exceptions=True)
        self._servers.clear()
        await self.firewall.close()

    def current_tuples(self):
        """(relationship_id, service_id, address, port) now — for `status`."""
        now = self.clock()
        return sorted(
            (e.relationship_id, e.service_id, e.address, e.port)
            for e in engine.responder_valid_set(self.identity, self.relationships.values(), now)
        )
