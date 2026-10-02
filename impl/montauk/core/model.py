# SPDX-License-Identifier: Apache-2.0
"""Data structures (§5)."""

import ipaddress
from dataclasses import dataclass
from enum import IntEnum

from . import crypto


@dataclass(frozen=True)
class IPv6Prefix:
    """Routing prefix (§5.4): high `length` bits significant, rest zero."""

    prefix: bytes  # 16 bytes
    length: int  # 0-128

    def __post_init__(self):
        if len(self.prefix) != 16:
            raise ValueError("prefix must be 16 bytes")
        if not 0 <= self.length <= 128:
            raise ValueError("prefix length must be 0-128")
        if int.from_bytes(self.prefix, "big") & self.host_mask:
            raise ValueError("bits below the prefix length must be zero")

    @property
    def host_mask(self) -> int:
        return (1 << (128 - self.length)) - 1

    @classmethod
    def from_string(cls, s: str) -> "IPv6Prefix":
        net = ipaddress.IPv6Network(s)
        return cls(net.network_address.packed, net.prefixlen)

    def __str__(self) -> str:
        return f"{ipaddress.IPv6Address(self.prefix)}/{self.length}"


class ReachabilityType(IntEnum):
    DIRECT = 0x01
    BROKERED = 0x02


@dataclass(frozen=True)
class Reachability:
    """§5.4. DIRECT requires prefix; BROKERED requires broker_pubkey,
    broker_prefix, and broker_guest_prior."""

    type: ReachabilityType
    prefix: IPv6Prefix | None = None
    broker_pubkey: bytes | None = None
    broker_prefix: IPv6Prefix | None = None
    broker_guest_prior: bytes | None = None

    def __post_init__(self):
        if self.type == ReachabilityType.DIRECT and self.prefix is None:
            raise ValueError("DIRECT reachability requires a prefix")
        if self.type == ReachabilityType.BROKERED and not (
            self.broker_pubkey and self.broker_prefix and self.broker_guest_prior
        ):
            raise ValueError("BROKERED reachability requires broker_pubkey, broker_prefix, broker_guest_prior")


@dataclass(frozen=True)
class ServiceDefinition:
    """§5.5."""

    service_id: bytes  # 16 bytes
    name: str
    protocol: int = 0x01  # 0x01 TCP, 0x02 UDP
    internal_target: str = ""

    def __post_init__(self):
        if len(self.service_id) != 16:
            raise ValueError("service_id must be 16 bytes")


@dataclass(frozen=True)
class Relationship:
    """§5.6. Immutable; revoke via dataclasses.replace(rel, revoked_at=now)."""

    relationship_id: bytes  # 16 bytes
    peer_pubkey: bytes  # 32 bytes
    prior: bytes  # 32 bytes
    handshake_password: bytes  # 32 bytes
    reachability: Reachability
    services: tuple[ServiceDefinition, ...] = ()
    created_at: int = 0
    revoked_at: int | None = None

    def service(self, service_id: bytes) -> ServiceDefinition:
        for svc in self.services:
            if svc.service_id == service_id:
                return svc
        raise KeyError(f"unknown service {service_id.hex()}")


@dataclass(frozen=True)
class Identity:
    """The local party: static keypair plus own routing prefix (responder role).

    Implementation construct — the spec keeps the local identity implicit.
    """

    static_private: bytes
    static_public: bytes
    prefix: IPv6Prefix | None = None

    @classmethod
    def from_private(cls, static_private: bytes, prefix: IPv6Prefix | None = None) -> "Identity":
        return cls(static_private, crypto.public_key(static_private), prefix)


@dataclass(frozen=True)
class ValidSetEntry:
    """§5.7: one (address, port) tuple valid for one bucket interval."""

    address: ipaddress.IPv6Address
    port: int
    relationship_id: bytes
    service_id: bytes
    valid_from: int
    valid_until: int
