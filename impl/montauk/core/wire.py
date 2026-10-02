# SPDX-License-Identifier: Apache-2.0
"""Framing and FirstPacket handling (§7.1-§7.2, §11.3-§11.5)."""

from dataclasses import dataclass

from .constants import (
    FIRST_PACKET_HEADER_LEN,
    MAX_FRAME_BODY,
    TIMESTAMP_TOLERANCE,
    VERSION,
)
from .errors import FrameError, PacketInvalid


def encode_frame(body: bytes) -> bytes:
    """§7.1: UINT16 big-endian length prefix, one message per frame."""
    if len(body) > MAX_FRAME_BODY:
        raise FrameError("frame body exceeds 65535 bytes")
    return len(body).to_bytes(2, "big") + body


class FrameDecoder:
    """Incremental frame extraction from a byte stream (§7.1).

    Receivers MUST NOT process a frame body until `length` bytes have been
    received — feed() only returns complete bodies.
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf.extend(data)
        frames = []
        while len(self._buf) >= 2:
            length = int.from_bytes(self._buf[:2], "big")
            if len(self._buf) < 2 + length:
                break
            frames.append(bytes(self._buf[2 : 2 + length]))
            del self._buf[: 2 + length]
        return frames

    @property
    def buffered(self) -> int:
        return len(self._buf)


@dataclass(frozen=True)
class FirstPacket:
    """§7.2. `header` is the exact 25 transmitted bytes — it is the Noise
    prologue (§4.4) and must never be re-serialized from the parsed fields."""

    version: int
    timestamp: int
    nonce: bytes
    payload: bytes
    header: bytes

    @property
    def prologue(self) -> bytes:
        return self.header


def encode_first_packet(version: int, timestamp: int, nonce: bytes, payload: bytes) -> bytes:
    """§7.2 wire format: version(1) || timestamp(8 BE) || nonce(16) || payload."""
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    return bytes([version]) + timestamp.to_bytes(8, "big") + nonce + payload


def parse_first_packet(body: bytes) -> FirstPacket:
    """Parse a frame body as a FirstPacket. Structural checks only —
    validate_first_packet() applies the §11.3-§11.5 rules."""
    if len(body) < FIRST_PACKET_HEADER_LEN:
        raise PacketInvalid("malformed")
    return FirstPacket(
        version=body[0],
        timestamp=int.from_bytes(body[1:9], "big"),
        nonce=bytes(body[9:25]),
        payload=bytes(body[25:]),
        header=bytes(body[:FIRST_PACKET_HEADER_LEN]),
    )


class NonceCache:
    """§11.4: reject nonces seen within the tolerance window. Entries are
    pruned once they are old enough that the timestamp check alone would
    reject any replay carrying them."""

    def __init__(self, tolerance: int = TIMESTAMP_TOLERANCE):
        self.tolerance = tolerance
        self._seen: dict[bytes, int] = {}

    def check_and_add(self, nonce: bytes, now: int) -> bool:
        """True if fresh (and records it); False if replayed."""
        self._prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _prune(self, now: int):
        horizon = now - 2 * self.tolerance
        stale = [n for n, seen_at in self._seen.items() if seen_at < horizon]
        for n in stale:
            del self._seen[n]

    def __len__(self) -> int:
        return len(self._seen)


def validate_first_packet(
    fp: FirstPacket,
    *,
    now: int,
    nonce_cache: NonceCache,
    version: int = VERSION,
):
    """§11.3-§11.5 in check order: version, timestamp window, nonce replay.
    The timestamp tolerance is the nonce cache's own tolerance, so the cache's
    retention horizon always covers the acceptance window (a wider validation
    tolerance can never outrun the cache and admit a replay). Any PacketInvalid
    raised here maps to a silent drop — no response, ever."""
    tolerance = nonce_cache.tolerance
    if fp.version != version:
        raise PacketInvalid("bad_version")
    if not (now - tolerance <= fp.timestamp <= now + tolerance):
        raise PacketInvalid("timestamp_out_of_window")
    if not nonce_cache.check_and_add(fp.nonce, now):
        raise PacketInvalid("nonce_replayed")
