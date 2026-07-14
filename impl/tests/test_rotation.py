# SPDX-License-Identifier: Apache-2.0
"""M2: live address rotation and clock-skew tolerance.

Rotation logic is driven by an injected clock (and, for the background loop, an
injected sleep), so a 5-minute bucket is exercised deterministically without
waiting. All sockets are IPv6 loopback (rootless).
"""

import asyncio
import contextlib

import pytest

from conftest import ORIGIN_BODY, http_get, make_relationship, start_origin

from montauk.client import LocalForward
from montauk.core import engine
from montauk.core.constants import BUCKET_DURATION
from montauk.daemon import MontaukDaemon

BUCKET_ALIGNED = 1706295600  # divisible by 300
MID_BUCKET = BUCKET_ALIGNED + 150  # 150s into a bucket: ±40 stays in-bucket


# --- pure timing logic (§6.1, §6.4) ---

def test_next_boundary():
    assert engine.next_boundary(BUCKET_ALIGNED) == BUCKET_ALIGNED + BUCKET_DURATION
    assert engine.next_boundary(BUCKET_ALIGNED + 1) == BUCKET_ALIGNED + BUCKET_DURATION
    assert engine.next_boundary(BUCKET_ALIGNED + 299) == BUCKET_ALIGNED + BUCKET_DURATION
    assert engine.next_boundary(BUCKET_ALIGNED + 300) == BUCKET_ALIGNED + 2 * BUCKET_DURATION


@pytest.mark.parametrize(
    "offset,expected",
    [(0, 300), (1, 299), (150, 150), (299, 1)],
)
def test_delay_until_next_sync(offset, expected):
    daemon = _daemon_only(lambda: BUCKET_ALIGNED + offset)
    assert daemon._delay_until_next_sync(BUCKET_ALIGNED + offset) == expected


def _daemon_only(clock, sleep=None):
    # A daemon with a dummy relationship, not started (no sockets bound yet).
    import os

    from montauk import pairing
    from montauk.core import crypto
    from montauk.core.model import ServiceDefinition

    service = ServiceDefinition(service_id=os.urandom(16), name="web", internal_target="127.0.0.1:9")
    _, _, bob, bob_rel = pairing.pair(
        crypto.generate_private_key(), crypto.generate_private_key(),
        services=(service,), bob_prefix="2001:db8:1234:5678::/64", alice_prefix="2001:db8:aaaa::/64",
    )
    return MontaukDaemon(bob, [bob_rel], clock=clock, sleep=sleep, bind_host="::1")


# --- the sliding window (§6.4) ---

async def _window_scenario():
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)
    clock = {"t": BUCKET_ALIGNED}
    daemon = MontaukDaemon(bob, [bob_rel], clock=lambda: clock["t"], bind_host="::1")
    await daemon.start(rotate=False)
    forward = LocalForward(alice, alice_rel, service.service_id, clock=lambda: clock["t"], connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    try:
        before = daemon.listening_ports()
        resp1 = await http_get(fhost, fport)

        clock["t"] += BUCKET_DURATION  # cross into the next bucket
        await daemon.sync()
        after = daemon.listening_ports()
        resp2 = await http_get(fhost, fport)
        return resp1, resp2, before, after
    finally:
        await forward.close()
        await daemon.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_connection_succeeds_across_boundary():
    resp1, resp2, before, after = asyncio.run(asyncio.wait_for(_window_scenario(), timeout=15))
    assert ORIGIN_BODY in resp1  # connected in bucket B
    assert ORIGIN_BODY in resp2  # connected in bucket B+1, after rotation
    assert before != after  # the window slid
    assert len(before & after) == 2  # buckets B and B+1 overlap (seamless handoff)
    assert len(before ^ after) == 2  # exactly B-1 retired, B+2 added


# --- background rotation loop fires at boundaries ---

async def _loop_scenario():
    calls = []
    clock = {"t": BUCKET_ALIGNED}

    async def fake_sleep(delay):
        calls.append(delay)
        clock["t"] += delay  # advance virtual time by exactly the requested delay
        if len(calls) >= 3:
            raise asyncio.CancelledError

    daemon = _daemon_only(lambda: clock["t"], sleep=fake_sleep)
    await daemon.start(rotate=False)  # initial sync only
    assert daemon._sync_count == 1
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await daemon._rotation_loop()
        return calls, daemon._sync_count
    finally:
        await daemon.close()


def test_rotation_loop_syncs_each_boundary():
    calls, sync_count = asyncio.run(asyncio.wait_for(_loop_scenario(), timeout=15))
    assert calls == [BUCKET_DURATION, BUCKET_DURATION, BUCKET_DURATION]
    assert sync_count == 3  # one re-sync per boundary (initial sync excluded by cancel)


# --- timestamp skew tolerance (§11.3) at the connection level ---

async def _skew_scenario(skew: int) -> bool:
    origin_server, origin_target = await start_origin()
    service, alice, alice_rel, bob, bob_rel = make_relationship(origin_target)
    # Daemon fixed mid-bucket; client offset by `skew` — small enough to stay in
    # the same address bucket, so only the FirstPacket timestamp gate is tested.
    daemon = MontaukDaemon(bob, [bob_rel], clock=lambda: MID_BUCKET, bind_host="::1")
    await daemon.start(rotate=False)
    forward = LocalForward(alice, alice_rel, service.service_id, clock=lambda: MID_BUCKET + skew, connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    try:
        return ORIGIN_BODY in await http_get(fhost, fport)
    finally:
        await forward.close()
        await daemon.close()
        origin_server.close()
        await origin_server.wait_closed()


@pytest.mark.parametrize(
    "skew,expect_success",
    [(0, True), (30, True), (-30, True), (40, False), (-40, False)],
)
def test_timestamp_skew_tolerance(skew, expect_success):
    got = asyncio.run(asyncio.wait_for(_skew_scenario(skew), timeout=15))
    assert got is expect_success
