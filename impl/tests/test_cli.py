# SPDX-License-Identifier: Apache-2.0
"""CLI: card round-trip and a pair -> serve -> connect e2e over loopback."""

import asyncio

from conftest import ORIGIN_BODY, http_get, start_origin

from montauk import cli, config
from montauk.client import LocalForward
from montauk.daemon import MontaukDaemon


def test_keygen(capsys):
    assert cli.main(["keygen"]) == 0
    out = capsys.readouterr().out
    assert "private:" in out and "public:" in out


def test_pair_writes_loadable_cards(tmp_path):
    resp = tmp_path / "bob.json"
    init = tmp_path / "alice.json"
    rc = cli.main([
        "pair", "--responder-prefix", "2001:db8:1234:5678::/64",
        "--service", "ssh=127.0.0.1:22", "--service", "web=127.0.0.1:80",
        "--out-responder", str(resp), "--out-initiator", str(init),
    ])
    assert rc == 0
    bob_id, bob_rels = config.load_card(str(resp))
    alice_id, alice_rels = config.load_card(str(init))
    # Cards are two views of one relationship: same id/prior/password, each
    # storing the other's public key.
    assert bob_id.prefix is not None
    assert bob_rels[0].relationship_id == alice_rels[0].relationship_id
    assert bob_rels[0].prior == alice_rels[0].prior
    assert bob_rels[0].peer_pubkey == alice_id.static_public
    assert alice_rels[0].peer_pubkey == bob_id.static_public
    rel, svc = config.find_service(alice_rels, "web")
    assert svc.name == "web"


async def _pair_serve_connect(tmp_path) -> bytes:
    origin_server, origin_target = await start_origin()
    resp = tmp_path / "bob.json"
    init = tmp_path / "alice.json"
    cli.main([
        "pair", "--responder-prefix", "2001:db8:1234:5678::/64",
        "--service", f"web={origin_target}",
        "--out-responder", str(resp), "--out-initiator", str(init),
    ])
    # Drive the loaded cards through the daemon/client directly in loopback mode
    # (equivalent to `montauk serve --bind-host ::1` and `montauk connect --connect-host ::1`).
    bob_id, bob_rels = config.load_card(str(resp))
    alice_id, alice_rels = config.load_card(str(init))
    rel, svc = config.find_service(alice_rels, "web")

    daemon = MontaukDaemon(bob_id, bob_rels, bind_host="::1")
    await daemon.start()
    forward = LocalForward(alice_id, rel, svc.service_id, connect_host="::1")
    fhost, fport = await forward.serve("127.0.0.1", 0)
    try:
        return await http_get(fhost, fport)
    finally:
        await forward.close()
        await daemon.close()
        origin_server.close()
        await origin_server.wait_closed()


def test_pair_then_direct_connection(tmp_path):
    body = asyncio.run(asyncio.wait_for(_pair_serve_connect(tmp_path), 15))
    assert b"200 OK" in body
    assert ORIGIN_BODY in body
