from __future__ import annotations

from shroud import cascade


def _seed_exit_state(ctx):
    ctx.role = "exit"
    ctx.state.set_ref("vless_uuid", "11111111-2222-3333-4444-555555555555")
    ctx.state.set_ref("reality_pbk", "PUBKEY")
    ctx.state.set_ref("reality_short_id", "abcd1234")
    ctx.state.set_ref("reality_sni", "dl.google.com")


def test_bundle_roundtrip_token(ctx, tmp_path):
    _seed_exit_state(ctx)
    token = cascade.write_bundle(ctx, tmp_path / "ci.json")
    assert token.startswith("shroud-exit://")
    loaded = cascade.load_bundle(token)
    assert loaded["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert loaded["reality"]["public_key"] == "PUBKEY"
    assert loaded["reality"]["sni"] == "dl.google.com"


def test_bundle_roundtrip_file(ctx, tmp_path):
    _seed_exit_state(ctx)
    path = tmp_path / "ci.json"
    cascade.write_bundle(ctx, path)
    loaded = cascade.load_bundle(str(path))
    assert loaded["address"] == ctx.facts.public_ip4
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_bundle_contains_no_admin_creds(ctx, tmp_path):
    _seed_exit_state(ctx)
    ctx.credentials["panel_pass"] = "TOPSECRETPANEL"
    token = cascade.write_bundle(ctx, tmp_path / "ci.json")
    import base64, json
    raw = base64.urlsafe_b64decode(token[len("shroud-exit://"):]).decode()
    assert "TOPSECRETPANEL" not in raw
    data = json.loads(raw)
    assert "panel" not in data and "credentials" not in data


def test_entry_outbound_has_empty_flow(ctx, tmp_path):
    _seed_exit_state(ctx)
    bundle = cascade.build_bundle(ctx)
    ob = cascade.entry_outbound_config(bundle)
    user = ob["settings"]["vnext"][0]["users"][0]
    assert user["flow"] == ""
    assert ob["streamSettings"]["network"] == "xhttp"
    assert ob["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY"
