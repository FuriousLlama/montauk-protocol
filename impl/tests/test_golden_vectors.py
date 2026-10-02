# SPDX-License-Identifier: Apache-2.0
"""Golden tests: the implementation must reproduce every spec §13 vector."""

import ipaddress

import pytest

from conftest import hx
from montauk.core import crypto, engine, noise, wire
from montauk.core.model import IPv6Prefix


def test_13_1_key_generation(vectors):
    v = vectors["key_generation"]
    assert crypto.public_key(hx(v["inputs"]["private_key"])).hex() == v["outputs"]["public_key"]


def test_13_2_shared_secret_both_directions(vectors):
    v = vectors["shared_secret"]
    alice_priv = hx(v["inputs"]["alice_private"])
    bob_priv = hx(v["inputs"]["bob_private"])
    shared = v["outputs"]["shared_secret"]
    assert crypto.dh(alice_priv, hx(v["inputs"]["bob_public"])).hex() == shared
    assert crypto.dh(bob_priv, hx(v["inputs"]["alice_public"])).hex() == shared
    assert crypto.public_key(alice_priv).hex() == v["inputs"]["alice_public"]
    assert crypto.public_key(bob_priv).hex() == v["inputs"]["bob_public"]


def test_13_3_session_key(vectors):
    v = vectors["session_key"]
    got = crypto.derive_session_key(hx(v["inputs"]["shared_secret"]), hx(v["inputs"]["prior"]))
    assert got.hex() == v["outputs"]["session_key"]


@pytest.mark.parametrize("case_index", [0, 1, 2], ids=["A_64", "B_80", "C_port_modulo"])
def test_13_4_address_generation(vectors, case_index):
    v = vectors["address_generation"]
    common, case = v["common"], v["cases"][case_index]
    session_key = hx(common["session_key"])
    responder_pubkey = hx(common["responder_pubkey"])
    service_id = hx(common["service_id"])
    raw = engine.address_raw(session_key, responder_pubkey, service_id, case["T"])
    assert raw.hex() == case["raw"]
    address, port = engine.compute_tuple(
        session_key, responder_pubkey, IPv6Prefix.from_string(case["prefix"]), service_id, case["T"]
    )
    assert address == ipaddress.IPv6Address(case["ipv6_address"])
    assert port == case["port"]
    assert engine.time_bucket(case["timestamp"]) == case["T"]


def test_13_5_first_packet(vectors):
    v = vectors["first_packet"]
    body = wire.encode_first_packet(
        v["inputs"]["version"], v["inputs"]["timestamp"], hx(v["inputs"]["nonce"]), hx(v["inputs"]["payload"])
    )
    assert body.hex() == v["outputs"]["frame_body"]
    assert wire.encode_frame(body).hex() == v["outputs"]["wire_format"]
    fp = wire.parse_first_packet(body)
    assert fp.version == v["inputs"]["version"]
    assert fp.timestamp == v["inputs"]["timestamp"]
    assert fp.nonce.hex() == v["inputs"]["nonce"]
    assert fp.payload.hex() == v["inputs"]["payload"]
    assert fp.prologue.hex() == v["outputs"]["noise_prologue"]


def _run_vector_handshake(v):
    inp = v["inputs"]
    initiator = noise.Handshake(
        initiator=True,
        prologue=hx(inp["prologue"]),
        static_private=hx(inp["init_static"]),
        psk=hx(inp["psk"]),
        remote_static=crypto.public_key(hx(inp["resp_static"])),
        ephemeral_private=hx(inp["init_ephemeral"]),
    )
    responder = noise.Handshake(
        initiator=False,
        prologue=hx(inp["prologue"]),
        static_private=hx(inp["resp_static"]),
        psk=hx(inp["psk"]),
        ephemeral_private=hx(inp["resp_ephemeral"]),
    )
    m1 = initiator.write_message(hx(inp["msg1_payload"]))
    assert responder.read_message(m1) == hx(inp["msg1_payload"])
    m2 = responder.write_message(hx(inp["msg2_payload"]))
    assert initiator.read_message(m2) == hx(inp["msg2_payload"])
    assert m1.hex() == v["outputs"]["message_1"]
    assert m2.hex() == v["outputs"]["message_2"]
    assert initiator.handshake_hash == responder.handshake_hash
    assert initiator.handshake_hash.hex() == v["outputs"]["handshake_hash"]
    # Responder learned the initiator's static identity through the handshake
    assert responder.remote_static == crypto.public_key(hx(inp["init_static"]))
    return initiator, responder


def test_13_6_handshake_direct(vectors):
    v = vectors["handshake_direct"]
    initiator, responder = _run_vector_handshake(v)
    i_send, i_recv = initiator.split()
    r_send, r_recv = responder.split()
    t1, t2 = v["outputs"]["transport_1"], v["outputs"]["transport_2"]
    ct1 = i_send.encrypt(b"", hx(t1["plaintext"]))
    assert ct1.hex() == t1["ciphertext"]
    assert r_recv.decrypt(b"", ct1) == hx(t1["plaintext"])
    ct2 = r_send.encrypt(b"", hx(t2["plaintext"]))
    assert ct2.hex() == t2["ciphertext"]
    assert i_recv.decrypt(b"", ct2) == hx(t2["plaintext"])


def test_13_7_handshake_brokered(vectors):
    v = vectors["handshake_brokered"]
    _run_vector_handshake(v)
    # Brokered message 1 payload is exactly the 16-byte service_id (§4.4)
    noise.check_message1_payload(hx(v["inputs"]["msg1_payload"]), brokered=True)
