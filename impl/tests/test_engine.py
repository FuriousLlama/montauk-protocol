# SPDX-License-Identifier: Apache-2.0
"""Engine tests: bucket math, valid-set window, directionality, revocation."""

import dataclasses
import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import hx
from montauk.core import engine
from montauk.core.constants import BUCKET_DURATION, PORT_MIN, PORT_RANGE
from montauk.core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)

PREFIX = "2001:db8:1234:5678::/64"


@pytest.fixture()
def parties(vectors):
    ss, hd = vectors["shared_secret"], vectors["handshake_direct"]
    addr = vectors["address_generation"]
    service_id = hx(addr["common"]["service_id"])
    alice = Identity.from_private(hx(ss["inputs"]["alice_private"]), IPv6Prefix.from_string("2001:db8:aaaa::/64"))
    bob = Identity.from_private(hx(ss["inputs"]["bob_private"]), IPv6Prefix.from_string(PREFIX))
    service = ServiceDefinition(service_id=service_id, name="photos", internal_target="127.0.0.1:8080")

    def rel_for(me: Identity, peer: Identity) -> Relationship:
        return Relationship(
            relationship_id=bytes(range(16)),
            peer_pubkey=peer.static_public,
            prior=hx(vectors["session_key"]["inputs"]["prior"]),
            handshake_password=hx(hd["inputs"]["psk"]),
            reachability=Reachability(ReachabilityType.DIRECT, prefix=peer.prefix),
            services=(service,),
            created_at=0,
        )

    return alice, bob, rel_for(alice, bob), rel_for(bob, alice), service


def test_6_1_time_bucket_boundaries():
    assert engine.time_bucket(1706295600) == 5687652  # exact boundary
    assert engine.time_bucket(1706295599) == 5687651
    assert engine.time_bucket(1706295600 + 299) == 5687652
    assert engine.time_bucket(1706295600 + 300) == 5687653


def test_6_4_window_is_three_contiguous_buckets(parties):
    alice, bob, rel_ab, rel_ba, service = parties
    now = 1706295600
    entries = sorted(engine.responder_valid_set(bob, [rel_ba], now), key=lambda e: e.valid_from)
    assert len(entries) == 3
    for entry, delta in zip(entries, (-1, 0, +1)):
        bucket = engine.time_bucket(now) + delta
        assert entry.valid_from == bucket * BUCKET_DURATION
        assert entry.valid_until == (bucket + 1) * BUCKET_DURATION
        assert entry.relationship_id == rel_ba.relationship_id
        assert entry.service_id == service.service_id


def test_6_5_role_separation(parties):
    """The two directions of one relationship must not collide (§6.5)."""
    alice, bob, rel_ab, rel_ba, service = parties
    now = 1706295600
    to_bob = engine.initiator_tuple(alice, rel_ab, service.service_id, now)
    to_alice = engine.initiator_tuple(bob, rel_ba, service.service_id, now)
    assert to_bob != to_alice
    assert to_bob[0] in ipaddress.IPv6Network(PREFIX)
    assert to_alice[0] in ipaddress.IPv6Network("2001:db8:aaaa::/64")


def test_13_4_initiator_tuple_matches_vector_a(vectors, parties):
    alice, bob, rel_ab, _, service = parties
    case = vectors["address_generation"]["cases"][0]
    address, port = engine.initiator_tuple(alice, rel_ab, service.service_id, case["timestamp"])
    assert address == ipaddress.IPv6Address(case["ipv6_address"])
    assert port == case["port"]


def test_13_4_responder_set_contains_vector_a_tuple(vectors, parties):
    _, bob, _, rel_ba, service = parties
    case = vectors["address_generation"]["cases"][0]
    entries = engine.responder_valid_set(bob, [rel_ba], case["timestamp"])
    tuples = {(e.address, e.port) for e in entries}
    assert (ipaddress.IPv6Address(case["ipv6_address"]), case["port"]) in tuples


def test_8_4_revocation_removes_all_entries(parties):
    _, bob, _, rel_ba, _ = parties
    revoked = dataclasses.replace(rel_ba, revoked_at=1706295601)
    assert engine.responder_valid_set(bob, [revoked], 1706295602) == frozenset()


def test_8_4_service_removal_removes_entries(parties):
    _, bob, _, rel_ba, _ = parties
    no_services = dataclasses.replace(rel_ba, services=())
    assert engine.responder_valid_set(bob, [no_services], 1706295600) == frozenset()


def test_valid_set_diff_across_bucket_rotation(parties):
    _, bob, _, rel_ba, _ = parties
    old = engine.responder_valid_set(bob, [rel_ba], 1706295600)
    new = engine.responder_valid_set(bob, [rel_ba], 1706295900)  # next bucket
    added, removed = engine.diff(old, new)
    assert len(added) == 1 and len(removed) == 1
    assert added <= new and removed <= old


def test_initiator_tuple_unknown_service_rejected(parties):
    alice, _, rel_ab, _, _ = parties
    with pytest.raises(KeyError):
        engine.initiator_tuple(alice, rel_ab, bytes(16), 1706295600)


@settings(max_examples=200, deadline=None)
@given(
    session_key=st.binary(min_size=32, max_size=32),
    responder_pubkey=st.binary(min_size=32, max_size=32),
    service_id=st.binary(min_size=16, max_size=16),
    T=st.integers(min_value=0, max_value=2**40),
    prefix_str=st.sampled_from(
        ["2001:db8::/48", "2001:db8:1234:5678::/64", "2001:db8:1:2:3::/80", "2001:db8::1:2:3:0/112", "2001:db8::1/128"]
    ),
)
def test_6_3_address_always_in_prefix_and_port_in_range(session_key, responder_pubkey, service_id, T, prefix_str):
    prefix = IPv6Prefix.from_string(prefix_str)
    address, port = engine.compute_tuple(session_key, responder_pubkey, prefix, service_id, T)
    assert address in ipaddress.IPv6Network(prefix_str)
    assert PORT_MIN <= port <= PORT_MIN + PORT_RANGE - 1  # 1024..65534 (§4.5)
