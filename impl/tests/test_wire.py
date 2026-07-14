# SPDX-License-Identifier: Apache-2.0
"""Framing and FirstPacket validation tests (§7.1-§7.2, §11.3-§11.5)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from montauk.core import wire
from montauk.core.errors import FrameError, PacketInvalid

NONCE = bytes(range(16))


def make_fp(version=0x01, timestamp=1_000_000, nonce=NONCE, payload=b"x" * 96):
    return wire.parse_first_packet(wire.encode_first_packet(version, timestamp, nonce, payload))


def test_7_1_frame_roundtrip_single_feed():
    frames = [b"", b"a", b"hello" * 100, b"\x00" * 65535]
    stream = b"".join(wire.encode_frame(f) for f in frames)
    assert wire.FrameDecoder().feed(stream) == frames


def test_7_1_oversized_frame_rejected():
    with pytest.raises(FrameError):
        wire.encode_frame(b"\x00" * 65536)


@settings(max_examples=100, deadline=None)
@given(
    payloads=st.lists(st.binary(max_size=300), min_size=1, max_size=6),
    data=st.data(),
)
def test_7_1_decoder_is_chunking_invariant(payloads, data):
    """Frame extraction must not depend on how the stream is sliced."""
    stream = b"".join(wire.encode_frame(p) for p in payloads)
    decoder = wire.FrameDecoder()
    got = []
    pos = 0
    while pos < len(stream):
        step = data.draw(st.integers(min_value=1, max_value=len(stream) - pos))
        got.extend(decoder.feed(stream[pos : pos + step]))
        pos += step
    assert got == payloads
    assert decoder.buffered == 0


def test_7_2_first_packet_roundtrip():
    fp = make_fp()
    assert fp.version == 0x01
    assert fp.timestamp == 1_000_000
    assert fp.nonce == NONCE
    assert fp.payload == b"x" * 96
    assert fp.header == fp.prologue
    assert len(fp.header) == 25


def test_7_2_short_body_is_malformed():
    with pytest.raises(PacketInvalid) as exc:
        wire.parse_first_packet(b"\x01" + b"\x00" * 23)  # 24 bytes < header size
    assert exc.value.reason == "malformed"


def test_11_5_unknown_version_rejected():
    cache = wire.NonceCache()
    with pytest.raises(PacketInvalid) as exc:
        wire.validate_first_packet(make_fp(version=0x02), now=1_000_000, nonce_cache=cache)
    assert exc.value.reason == "bad_version"


@pytest.mark.parametrize("skew,ok", [(0, True), (-30, True), (30, True), (-31, False), (31, False)])
def test_11_3_timestamp_window_inclusive(skew, ok):
    now = 1_000_000
    cache = wire.NonceCache(tolerance=30)
    fp = make_fp(timestamp=now + skew)
    if ok:
        wire.validate_first_packet(fp, now=now, nonce_cache=cache, tolerance=30)
    else:
        with pytest.raises(PacketInvalid) as exc:
            wire.validate_first_packet(fp, now=now, nonce_cache=cache, tolerance=30)
        assert exc.value.reason == "timestamp_out_of_window"


def test_11_4_nonce_replay_rejected():
    now = 1_000_000
    cache = wire.NonceCache()
    wire.validate_first_packet(make_fp(timestamp=now), now=now, nonce_cache=cache)
    with pytest.raises(PacketInvalid) as exc:
        wire.validate_first_packet(make_fp(timestamp=now + 1), now=now, nonce_cache=cache)
    assert exc.value.reason == "nonce_replayed"
    # A different nonce is fine
    wire.validate_first_packet(make_fp(nonce=bytes(range(16, 32))), now=now, nonce_cache=cache)


def test_11_4_nonce_cache_expires_entries():
    cache = wire.NonceCache(tolerance=30)
    assert cache.check_and_add(NONCE, now=1_000)
    assert len(cache) == 1
    # Well past the retention horizon: entry pruned; the timestamp check is
    # what rejects such a stale replay, not the cache (§11.4).
    assert cache.check_and_add(bytes(range(16, 32)), now=2_000)
    assert len(cache) == 1
