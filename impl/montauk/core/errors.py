# SPDX-License-Identifier: Apache-2.0
"""Typed errors. The daemon maps every one of these to the single silent-drop
funnel (§11.5); the reason strings exist for local logging only and MUST never
reach the wire."""


class MontaukError(Exception):
    """Base class for all protocol errors."""


class FrameError(MontaukError):
    """Framing violation (§7.1): oversized body or malformed length prefix."""


class PacketInvalid(MontaukError):
    """First packet failed validation (§11.3-§11.5). Carries a reason code:
    malformed | bad_version | timestamp_out_of_window | nonce_replayed."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class HandshakeError(MontaukError):
    """Noise handshake failure (§4.4): AEAD failure, payload rule violation,
    or protocol misuse. Connections are closed silently (§11.5)."""
