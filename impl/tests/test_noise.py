# SPDX-License-Identifier: Apache-2.0
"""Handshake behavior tests (§4.4): prologue binding, PSK, payload rules."""

import pytest

from conftest import hx
from montauk.core import crypto, noise
from montauk.core.errors import HandshakeError


@pytest.fixture()
def keys(vectors):
    inp = vectors["handshake_direct"]["inputs"]
    return {
        "init_static": hx(inp["init_static"]),
        "resp_static": hx(inp["resp_static"]),
        "resp_static_pub": crypto.public_key(hx(inp["resp_static"])),
        "psk": hx(inp["psk"]),
        "prologue": hx(inp["prologue"]),
    }


def make_pair(keys, *, resp_prologue=None, resp_psk=None):
    initiator = noise.Handshake(
        initiator=True,
        prologue=keys["prologue"],
        static_private=keys["init_static"],
        psk=keys["psk"],
        remote_static=keys["resp_static_pub"],
    )
    responder = noise.Handshake(
        initiator=False,
        prologue=resp_prologue if resp_prologue is not None else keys["prologue"],
        static_private=keys["resp_static"],
        psk=resp_psk if resp_psk is not None else keys["psk"],
    )
    return initiator, responder


def test_4_4_full_handshake_with_generated_ephemerals(keys):
    initiator, responder = make_pair(keys)
    m1 = initiator.write_message(b"")
    assert responder.read_message(m1) == b""
    m2 = responder.write_message(b"")
    assert initiator.read_message(m2) == b""
    assert initiator.handshake_hash == responder.handshake_hash
    i_send, i_recv = initiator.split()
    r_send, r_recv = responder.split()
    assert r_recv.decrypt(b"", i_send.encrypt(b"", b"ping")) == b"ping"
    assert i_recv.decrypt(b"", r_send.encrypt(b"", b"pong")) == b"pong"


def test_4_4_prologue_binding_rejects_restamped_header(keys):
    """A replayed message 1 under a re-stamped FirstPacket header must fail
    AEAD at the responder — the core replay defense of §4.4."""
    tampered = bytearray(keys["prologue"])
    tampered[-1] ^= 0x01  # attacker rewrites one nonce byte
    initiator, responder = make_pair(keys, resp_prologue=bytes(tampered))
    m1 = initiator.write_message(b"")
    with pytest.raises(HandshakeError):
        responder.read_message(m1)


def test_4_4_wrong_psk_fails_at_message_2(keys):
    """psk2 mixes the PSK in message 2: message 1 succeeds either way, the
    initiator detects the mismatch when reading message 2."""
    initiator, responder = make_pair(keys, resp_psk=bytes(32))
    m1 = initiator.write_message(b"")
    assert responder.read_message(m1) == b""  # PSK not yet in play
    m2 = responder.write_message(b"")
    with pytest.raises(HandshakeError):
        initiator.read_message(m2)


def test_4_4_out_of_order_use_rejected(keys):
    initiator, responder = make_pair(keys)
    with pytest.raises(HandshakeError):
        initiator.read_message(b"\x00" * 48)  # initiator writes first in IK
    m1 = initiator.write_message(b"")
    with pytest.raises(HandshakeError):
        responder.write_message(b"")  # responder must read message 1 first
    responder.read_message(m1)
    with pytest.raises(HandshakeError):
        initiator.split()  # not finished yet


def test_4_4_payload_rules():
    noise.check_message1_payload(b"", brokered=False)
    noise.check_message1_payload(bytes(16), brokered=True)
    noise.check_message2_payload(b"")
    with pytest.raises(HandshakeError):
        noise.check_message1_payload(b"x", brokered=False)
    with pytest.raises(HandshakeError):
        noise.check_message1_payload(bytes(15), brokered=True)
    with pytest.raises(HandshakeError):
        noise.check_message1_payload(bytes(17), brokered=True)
    with pytest.raises(HandshakeError):
        noise.check_message2_payload(b"\x00")
