# SPDX-License-Identifier: Apache-2.0
"""Out-of-band relationship establishment (§8.1).

A relationship is symmetric: both parties hold the same relationship_id,
prior, handshake_password, and service definitions, and each stores the
other's public key and reachability. `pair()` mints both halves at once,
which is what a QR/NFC exchange or a card import produces.
"""

import os

from .core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)


def pair(
    alice_private: bytes,
    bob_private: bytes,
    *,
    services: tuple[ServiceDefinition, ...],
    bob_prefix: str,
    alice_prefix: str | None = None,
    prior: bytes | None = None,
    handshake_password: bytes | None = None,
    relationship_id: bytes | None = None,
    created_at: int = 0,
) -> tuple[Identity, Relationship, Identity, Relationship]:
    """Return (alice_identity, alice_relationship, bob_identity, bob_relationship).

    Bob is the responder in this example (he offers `services` on `bob_prefix`).
    Alice gets a prefix too so the relationship is bidirectional-capable.
    """
    prior = prior if prior is not None else os.urandom(32)
    handshake_password = handshake_password if handshake_password is not None else os.urandom(32)
    relationship_id = relationship_id if relationship_id is not None else os.urandom(16)

    alice = Identity.from_private(alice_private, IPv6Prefix.from_string(alice_prefix) if alice_prefix else None)
    bob = Identity.from_private(bob_private, IPv6Prefix.from_string(bob_prefix))

    alice_rel = Relationship(
        relationship_id=relationship_id,
        peer_pubkey=bob.static_public,
        prior=prior,
        handshake_password=handshake_password,
        reachability=Reachability(ReachabilityType.DIRECT, prefix=bob.prefix),
        services=services,
        created_at=created_at,
    )
    bob_rel = Relationship(
        relationship_id=relationship_id,
        peer_pubkey=alice.static_public,
        prior=prior,
        handshake_password=handshake_password,
        reachability=Reachability(ReachabilityType.DIRECT, prefix=alice.prefix or bob.prefix),
        services=services,
        created_at=created_at,
    )
    return alice, alice_rel, bob, bob_rel
