# SPDX-License-Identifier: Apache-2.0
"""Initiator client: a local port-forward over Montauk (the `ssh -L` model).

Each local connection triggers a fresh Montauk connection to the peer's
current computed tuple, a handshake, and a bidirectional proxy. `connect_host`
overrides the computed IPv6 address with a single host (e.g. "::1") for
rootless local testing, where only the computed port is used.
"""

import asyncio
import logging

from . import transport
from .core import engine
from .core.model import Identity, Relationship

log = logging.getLogger("montauk.client")


class LocalForward:
    def __init__(
        self,
        identity: Identity,
        relationship: Relationship,
        service_id: bytes,
        *,
        clock=None,
        connect_host: str | None = None,
    ):
        relationship.service(service_id)  # fail early if the service is unknown
        self.identity = identity
        self.relationship = relationship
        self.service_id = service_id
        self.clock = clock or transport._now
        self.connect_host = connect_host
        self._server = None

    async def serve(self, local_host: str, local_port: int) -> tuple[str, int]:
        """Start listening locally; returns the actual bound (host, port)."""
        self._server = await asyncio.start_server(self._on_local, local_host, local_port)
        host, port = self._server.sockets[0].getsockname()[:2]
        log.info("forwarding [%s]:%d -> %s (service %s)", host, port, self._peer_label(), self.service_id.hex()[:8])
        return host, port

    def _peer_label(self) -> str:
        return self.relationship.peer_pubkey.hex()[:8]

    async def _on_local(self, local_reader, local_writer) -> None:
        channel_writer = None
        try:
            now = self.clock()
            address, port = engine.initiator_tuple(self.identity, self.relationship, self.service_id, now)
            host = self.connect_host or str(address)
            channel_reader, channel_writer = await asyncio.open_connection(host, port)
            send_cs, recv_cs = await transport.do_initiator_handshake(
                channel_reader, channel_writer,
                identity=self.identity,
                relationship=self.relationship,
                service_id=self.service_id,
                now=now,
            )
        except Exception as exc:
            log.debug("forward attempt failed: %s", exc)
            local_writer.close()
            if channel_writer is not None:
                channel_writer.close()
            return

        try:
            await transport.proxy(channel_reader, channel_writer, send_cs, recv_cs, local_reader, local_writer)
        finally:
            channel_writer.close()
            local_writer.close()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
