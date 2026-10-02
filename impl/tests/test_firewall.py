# SPDX-License-Identifier: Apache-2.0
"""nftables firewall backend: command generation, order, and timeouts.

Runs without root by injecting a recording runner in place of the nft
subprocess — the actual nft execution is exercised by the netns harness.
"""

import asyncio
import ipaddress

from montauk.core.model import IPv6Prefix, ValidSetEntry
from montauk.firewall import NftablesFirewall

PREFIX = IPv6Prefix.from_string("2001:db8:1234:5678::/64")


class Recorder:
    def __init__(self):
        self.batches: list[list[str]] = []

    async def __call__(self, commands):
        self.batches.append(list(commands))

    @property
    def flat(self) -> str:
        return "\n".join(c for batch in self.batches for c in batch)


def entry(addr: str, port: int, valid_until: int) -> ValidSetEntry:
    return ValidSetEntry(
        address=ipaddress.IPv6Address(addr),
        port=port,
        relationship_id=bytes(16),
        service_id=bytes(16),
        valid_from=0,
        valid_until=valid_until,
    )


def test_start_builds_default_drop_ruleset():
    rec = Recorder()
    asyncio.run(NftablesFirewall(PREFIX, run=rec).start())
    flat = rec.flat
    assert "add set ip6 montauk valid { type ipv6_addr . inet_service; flags timeout; }" in flat
    # established connections keep their path; new connections to valid tuples
    # are accepted; everything else to the prefix is dropped (silent).
    assert "ct state established,related accept" in flat
    assert "ip6 daddr . tcp dport @valid accept" in flat
    assert "ip6 daddr 2001:db8:1234:5678::/64 drop" in flat
    # ordering: established accept, then valid accept, then drop
    assert flat.index("established,related accept") < flat.index("@valid accept") < flat.index("drop")


def test_allow_timeout_spans_the_full_window():
    rec = Recorder()
    # valid_until is the bucket end; the element must live one bucket longer (the
    # window end) so the listener's whole lifetime is covered. now=700 ->
    # 1000 + 300 - 700 = 600s.
    e = entry("2001:db8:1234:5678::abcd", 40000, valid_until=1000)
    asyncio.run(NftablesFirewall(PREFIX, run=rec).allow([e], now=700))
    assert rec.batches == [
        ["add element ip6 montauk valid { 2001:db8:1234:5678::abcd . 40000 timeout 600s }"]
    ]


def test_allow_clamps_timeout_to_at_least_one_second():
    rec = Recorder()
    e = entry("2001:db8:1234:5678::1", 1024, valid_until=500)
    # now past the window end (500 + 300): 500 + 300 - 900 = -100 -> clamped to 1s.
    asyncio.run(NftablesFirewall(PREFIX, run=rec).allow([e], now=900))
    assert "timeout 1s" in rec.flat


def test_revoke_deletes_element_without_timeout():
    rec = Recorder()
    e = entry("2001:db8:1234:5678::abcd", 40000, valid_until=1000)
    asyncio.run(NftablesFirewall(PREFIX, run=rec).revoke([e]))
    assert rec.batches == [["delete element ip6 montauk valid { 2001:db8:1234:5678::abcd . 40000 }"]]


def test_allow_and_revoke_are_noops_for_empty_sets():
    rec = Recorder()
    asyncio.run(NftablesFirewall(PREFIX, run=rec).allow([], now=0))
    asyncio.run(NftablesFirewall(PREFIX, run=rec).revoke([]))
    assert rec.batches == []
