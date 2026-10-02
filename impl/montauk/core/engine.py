# SPDX-License-Identifier: Apache-2.0
"""Address generation and valid-set computation (§6, §5.7).

Pure functions of (relationships, time): no sockets, no clock reads. The
daemon feeds a real clock and applies the resulting diffs to listeners and
the firewall.
"""

import ipaddress
from collections.abc import Iterable

from . import crypto
from .constants import ADDRESS_INFO, BUCKET_DURATION, PORT_MIN, PORT_RANGE
from .model import Identity, IPv6Prefix, Relationship, ReachabilityType, ValidSetEntry

# §6.4: window of current bucket ±1
WINDOW = (-1, 0, +1)


def time_bucket(timestamp: int) -> int:
    """§6.1: T = floor(timestamp / BUCKET_DURATION)."""
    return timestamp // BUCKET_DURATION


def next_boundary(timestamp: int) -> int:
    """The next bucket boundary strictly after `timestamp` — when the address
    window slides and the responder should re-sync listeners (§6.4)."""
    return (time_bucket(timestamp) + 1) * BUCKET_DURATION


def address_raw(session_key: bytes, responder_pubkey: bytes, service_id: bytes, T: int) -> bytes:
    """§6.3: raw = HMAC-SHA256(session_key, T || ADDRESS_INFO || responder_pubkey || service_id)."""
    data = T.to_bytes(8, "big") + ADDRESS_INFO + responder_pubkey + service_id
    return crypto.hmac_sha256(session_key, data)


def compute_tuple(
    session_key: bytes,
    responder_pubkey: bytes,
    responder_prefix: IPv6Prefix,
    service_id: bytes,
    T: int,
) -> tuple[ipaddress.IPv6Address, int]:
    """§6.3: (address, port) for one bucket, constrained to the responder prefix."""
    raw = address_raw(session_key, responder_pubkey, service_id, T)
    addr_int = int.from_bytes(responder_prefix.prefix, "big") | (
        int.from_bytes(raw[:16], "big") & responder_prefix.host_mask
    )
    port_raw = (raw[16] << 8) | raw[17]
    port = PORT_MIN + (port_raw % PORT_RANGE)
    return ipaddress.IPv6Address(addr_int), port


def relationship_session_key(identity: Identity, relationship: Relationship) -> bytes:
    """§6.2: session key from the static-static ECDH and the Prior."""
    shared = crypto.dh(identity.static_private, relationship.peer_pubkey)
    return crypto.derive_session_key(shared, relationship.prior)


def responder_valid_set(
    identity: Identity, relationships: Iterable[Relationship], now: int
) -> frozenset[ValidSetEntry]:
    """§6.4, §6.5: all tuples this party must accept at `now` — one entry per
    (relationship, service, bucket) with the local party as responder.
    Revoked relationships contribute nothing (§8.4)."""
    if identity.prefix is None:
        raise ValueError("identity has no routing prefix; cannot act as responder")
    T = time_bucket(now)
    entries = []
    for rel in relationships:
        if rel.revoked_at is not None:
            continue
        session_key = relationship_session_key(identity, rel)
        for svc in rel.services:
            for delta in WINDOW:
                bucket = T + delta
                address, port = compute_tuple(
                    session_key, identity.static_public, identity.prefix, svc.service_id, bucket
                )
                entries.append(
                    ValidSetEntry(
                        address=address,
                        port=port,
                        relationship_id=rel.relationship_id,
                        service_id=svc.service_id,
                        valid_from=bucket * BUCKET_DURATION,
                        valid_until=(bucket + 1) * BUCKET_DURATION,
                    )
                )
    return frozenset(entries)


def initiator_tuple(
    identity: Identity, relationship: Relationship, service_id: bytes, now: int
) -> tuple[ipaddress.IPv6Address, int]:
    """§6.5: the peer-as-responder tuple to connect to at `now` (direct only)."""
    relationship.service(service_id)  # must be a defined service
    reach = relationship.reachability
    if reach.type != ReachabilityType.DIRECT:
        raise NotImplementedError("brokered connections arrive with milestone M5")
    session_key = relationship_session_key(identity, relationship)
    return compute_tuple(session_key, relationship.peer_pubkey, reach.prefix, service_id, time_bucket(now))


def diff(
    old: frozenset[ValidSetEntry], new: frozenset[ValidSetEntry]
) -> tuple[frozenset[ValidSetEntry], frozenset[ValidSetEntry]]:
    """(added, removed) between two valid sets; the daemon turns these into
    listener binds/closes and firewall element add/removes."""
    return frozenset(new - old), frozenset(old - new)
