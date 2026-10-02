# SPDX-License-Identifier: Apache-2.0
"""Firewall backends for the valid set (§3.2, §11.5, §11.6).

The valid set is enforced in the kernel: a default-drop on the responder's
prefix plus an accept for exactly the currently-valid (address, port) tuples.
Each tuple is installed with a timeout equal to its remaining validity, so if
the daemon crashes the kernel expires the holes on its own — fail-closed.

Two backends: NullFirewall (default; relies on the bind alone, for loopback
tests and hosts without nftables) and NftablesFirewall (real enforcement).
"""

import asyncio
from typing import Iterable, Protocol

from .core.constants import BUCKET_DURATION
from .core.errors import MontaukError
from .core.model import IPv6Prefix, ValidSetEntry


class FirewallError(MontaukError):
    pass


class Firewall(Protocol):
    async def start(self) -> None: ...
    async def allow(self, entries: Iterable[ValidSetEntry], now: int) -> None: ...
    async def revoke(self, entries: Iterable[ValidSetEntry]) -> None: ...
    async def close(self) -> None: ...


class NullFirewall:
    """No kernel filtering: only the socket bind gates connections. Correct on
    loopback (nothing else routes to ::1) and as a fallback where nft is
    unavailable, but it does NOT provide silent rejection on a routed prefix."""

    async def start(self) -> None:
        pass

    async def allow(self, entries: Iterable[ValidSetEntry], now: int) -> None:
        pass

    async def revoke(self, entries: Iterable[ValidSetEntry]) -> None:
        pass

    async def close(self) -> None:
        pass


async def _run_nft(commands: list[str]) -> None:
    script = ("\n".join(commands) + "\n").encode()
    proc = await asyncio.create_subprocess_exec(
        "nft", "-f", "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate(script)
    if proc.returncode != 0:
        raise FirewallError(f"nft failed: {err.decode().strip()}")


class NftablesFirewall:
    """Enforces the valid set as an nftables set with per-element timeouts.

    Ruleset (family ip6, table `montauk`):
        set valid { type ipv6_addr . inet_service; flags timeout; }
        chain input { hook input; policy accept;
            ip6 daddr . tcp dport @valid accept   # valid tuple -> through
            ip6 daddr <prefix> drop }             # anything else in-prefix -> silent
    Dropping the SYN at the input hook means the stack never generates a RST,
    so a scanner sees nothing (§11.5).
    """

    def __init__(self, prefix: IPv6Prefix, *, table: str = "montauk", run=None):
        self.prefix = prefix
        self.table = table
        self._run = run or _run_nft

    @staticmethod
    def _elem(entry: ValidSetEntry) -> str:
        return f"{entry.address} . {entry.port}"

    async def start(self) -> None:
        # Clean slate: drop any table left over from a prior run, then build fresh.
        try:
            await self._run([f"delete table ip6 {self.table}"])
        except FirewallError:
            pass
        await self._run(
            [
                f"add table ip6 {self.table}",
                f"add set ip6 {self.table} valid {{ type ipv6_addr . inet_service; flags timeout; }}",
                f"add chain ip6 {self.table} input {{ type filter hook input priority 0; policy accept; }}",
                # An established connection keeps its inbound path even after its
                # tuple leaves the valid set (§8.4: in-flight connections continue).
                f"add rule ip6 {self.table} input ct state established,related accept",
                # A new connection to a currently-valid tuple is accepted.
                f"add rule ip6 {self.table} input ip6 daddr . tcp dport @valid accept",
                # Anything else to the prefix is dropped silently (§11.5).
                f"add rule ip6 {self.table} input ip6 daddr {self.prefix} drop",
            ]
        )

    async def allow(self, entries: Iterable[ValidSetEntry], now: int) -> None:
        cmds = []
        for e in entries:
            # The element must live as long as its listener, i.e. until the tuple
            # leaves the ±1-bucket window (one bucket past its own validity), so
            # the trailing half of the window is not dropped early. The timeout is
            # a crash fail-safe; rotation removes the element explicitly.
            timeout = max(1, e.valid_until + BUCKET_DURATION - now)
            cmds.append(f"add element ip6 {self.table} valid {{ {self._elem(e)} timeout {timeout}s }}")
        if cmds:
            await self._run(cmds)

    async def revoke(self, entries: Iterable[ValidSetEntry]) -> None:
        cmds = [f"delete element ip6 {self.table} valid {{ {self._elem(e)} }}" for e in entries]
        if cmds:
            # Elements may already have expired; deleting a missing element errors,
            # so tolerate failure here.
            try:
                await self._run(cmds)
            except FirewallError:
                pass

    async def close(self) -> None:
        try:
            await self._run([f"delete table ip6 {self.table}"])
        except FirewallError:
            pass
