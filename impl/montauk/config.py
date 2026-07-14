# SPDX-License-Identifier: Apache-2.0
"""Relationship card (de)serialization for the CLI (§8.1).

A card is one party's local configuration: its identity (private key, and a
routing prefix if it acts as a responder) plus the relationships it holds. It
is the persisted form of the out-of-band exchange.
"""

import json

from .core import crypto
from .core.model import (
    Identity,
    IPv6Prefix,
    Reachability,
    ReachabilityType,
    Relationship,
    ServiceDefinition,
)


def _h(b: bytes) -> str:
    return b.hex()


def _prefix_to_str(p: IPv6Prefix | None) -> str | None:
    return str(p) if p is not None else None


def _prefix_from_str(s: str | None) -> IPv6Prefix | None:
    return IPv6Prefix.from_string(s) if s else None


def _service_to_json(s: ServiceDefinition) -> dict:
    return {
        "service_id": _h(s.service_id),
        "name": s.name,
        "protocol": s.protocol,
        "internal_target": s.internal_target,
    }


def _service_from_json(d: dict) -> ServiceDefinition:
    return ServiceDefinition(
        service_id=bytes.fromhex(d["service_id"]),
        name=d["name"],
        protocol=d.get("protocol", 0x01),
        internal_target=d.get("internal_target", ""),
    )


def _reach_to_json(r: Reachability) -> dict:
    return {
        "type": r.type.name,
        "prefix": _prefix_to_str(r.prefix),
        "broker_pubkey": _h(r.broker_pubkey) if r.broker_pubkey else None,
        "broker_prefix": _prefix_to_str(r.broker_prefix),
        "broker_guest_prior": _h(r.broker_guest_prior) if r.broker_guest_prior else None,
    }


def _reach_from_json(d: dict) -> Reachability:
    return Reachability(
        type=ReachabilityType[d["type"]],
        prefix=_prefix_from_str(d.get("prefix")),
        broker_pubkey=bytes.fromhex(d["broker_pubkey"]) if d.get("broker_pubkey") else None,
        broker_prefix=_prefix_from_str(d.get("broker_prefix")),
        broker_guest_prior=bytes.fromhex(d["broker_guest_prior"]) if d.get("broker_guest_prior") else None,
    )


def _relationship_to_json(r: Relationship) -> dict:
    return {
        "relationship_id": _h(r.relationship_id),
        "peer_pubkey": _h(r.peer_pubkey),
        "prior": _h(r.prior),
        "handshake_password": _h(r.handshake_password),
        "reachability": _reach_to_json(r.reachability),
        "services": [_service_to_json(s) for s in r.services],
        "created_at": r.created_at,
        "revoked_at": r.revoked_at,
    }


def _relationship_from_json(d: dict) -> Relationship:
    return Relationship(
        relationship_id=bytes.fromhex(d["relationship_id"]),
        peer_pubkey=bytes.fromhex(d["peer_pubkey"]),
        prior=bytes.fromhex(d["prior"]),
        handshake_password=bytes.fromhex(d["handshake_password"]),
        reachability=_reach_from_json(d["reachability"]),
        services=tuple(_service_from_json(s) for s in d["services"]),
        created_at=d.get("created_at", 0),
        revoked_at=d.get("revoked_at"),
    )


def save_card(path: str, identity: Identity, relationships) -> None:
    doc = {
        "identity": {
            "private": _h(identity.static_private),
            "public": _h(identity.static_public),
            "prefix": _prefix_to_str(identity.prefix),
        },
        "relationships": [_relationship_to_json(r) for r in relationships],
    }
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)


def load_card(path: str) -> tuple[Identity, list[Relationship]]:
    with open(path) as f:
        doc = json.load(f)
    ident = doc["identity"]
    identity = Identity.from_private(bytes.fromhex(ident["private"]), _prefix_from_str(ident.get("prefix")))
    relationships = [_relationship_from_json(r) for r in doc.get("relationships", [])]
    return identity, relationships


def find_service(relationships, name: str) -> tuple[Relationship, ServiceDefinition]:
    for rel in relationships:
        for svc in rel.services:
            if svc.name == name:
                return rel, svc
    raise KeyError(f"no service named {name!r} in card")
