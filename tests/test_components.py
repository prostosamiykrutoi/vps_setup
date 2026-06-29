from __future__ import annotations

import pytest

from shroud.components.telemt import TelemtComponent
from shroud.components.hysteria2 import Hysteria2Component
from shroud.components.xray_3xui import Xray3xuiComponent
from shroud.components import registry
from shroud import reality, paths


def _proto(ctx, pid):
    return ctx.profile.protocol(pid)


def test_telemt_link_is_faketls_ee(ctx):
    c = TelemtComponent(ctx, _proto(ctx, "telemt-mtproto"))
    c.prepare_secrets()
    links = c.links()
    assert links and links[0][1].startswith("tg://proxy?")
    # FakeTLS secret carries the 'ee' prefix + hex(domain).
    assert "secret=ee" in links[0][1]


def test_hysteria_link_and_udp_port(ctx):
    c = Hysteria2Component(ctx, _proto(ctx, "hysteria2"))
    c.prepare_secrets()
    assert c.firewall_ports() == [(8443, "udp")]
    assert c.links()[0][1].startswith("hy2://")


def test_vless_link_has_empty_flow_and_xhttp(ctx, monkeypatch):
    # Avoid needing cryptography/docker in CI: inject a deterministic keypair.
    monkeypatch.setattr(reality, "generate_keypair",
                        lambda c: ("PRIV_KEY_B64", "PUB_KEY_B64"))
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    c.prepare_secrets()
    uri = c.links()[0][1]
    assert uri.startswith("vless://")
    assert "type=xhttp" in uri
    assert "security=reality" in uri
    assert "pbk=PUB_KEY_B64" in uri
    # flow must NOT appear as xtls-rprx-vision for xhttp.
    assert "xtls-rprx-vision" not in uri


def test_vless_inbound_payload_flow_empty(ctx, monkeypatch):
    monkeypatch.setattr(reality, "generate_keypair",
                        lambda c: ("PRIV", "PUB"))
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    c.prepare_secrets()
    import json
    inbound = c._build_inbound()
    settings = json.loads(inbound["settings"])
    assert settings["clients"][0]["flow"] == ""
    stream = json.loads(inbound["streamSettings"])
    assert stream["network"] == "xhttp"
    assert stream["security"] == "reality"


def test_panel_port_not_in_firewall(ctx, monkeypatch):
    monkeypatch.setattr(reality, "generate_keypair", lambda c: ("PRIV", "PUB"))
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    ports = dict(c.firewall_ports())
    assert 2053 not in ports          # panel stays loopback
    assert 443 in ports               # inbound is public


def test_registry_builds_enabled(ctx):
    comps = registry.build_enabled(ctx)
    types = {c.type for c in comps}
    assert {"vless", "hysteria2", "telemt"}.issubset(types)


def test_panel_creds_written_as_bcrypt(ctx, monkeypatch, tmp_path):
    # Real-VPS bug: creds were set via a non-existent `x-ui setting` CLI, so the
    # panel kept its default admin. Now we bcrypt-write the users table directly.
    bcrypt = pytest.importorskip("bcrypt")
    import sqlite3
    monkeypatch.setattr(reality, "generate_keypair", lambda c: ("PRIV", "PUB"))
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    c.prepare_secrets()

    db = tmp_path / "x-ui.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                "password TEXT, login_epoch INTEGER)")
    con.execute("INSERT INTO users (username,password,login_epoch) "
                "VALUES ('admin','$2a$10$old',0)")
    con.commit(); con.close()

    assert c._set_panel_creds_db(db) is True

    con = sqlite3.connect(db)
    user, pwd_hash = con.execute("SELECT username,password FROM users").fetchone()
    con.close()
    assert user == c._panel_user                       # our username, not 'admin'
    assert pwd_hash.startswith("$2a$")                 # 3x-ui-compatible bcrypt
    assert bcrypt.checkpw(c._panel_pass.encode(), pwd_hash.encode())


def test_sni_validator_rejects_junk():
    from shroud.components import sni
    # The real-VPS bug: "TLS 1.3" was accepted as a donor SNI. It must not be.
    assert not sni.is_valid_domain("TLS 1.3")
    assert not sni.is_valid_domain("1.2.3.4")          # an IP is not a donor
    assert not sni.is_valid_domain("")
    assert not sni.is_valid_domain("www.microsoft.com")  # forbidden donor
    assert sni.is_valid_domain("dl.google.com")
    assert sni.is_valid_domain("*.fastly.net")          # wildcard cert -> apex
    assert sni.is_valid_domain("a.b.c.example.co.uk")


def test_panel_settings_parse_random_base_path(ctx, monkeypatch):
    # The CI failure was a 403 because 3x-ui generated a random webBasePath and
    # we hit /login. _read_panel_settings must recover the real port + base path.
    from shroud.proc import Result
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    sample = "username: adm_x\nport: 2053\nwebBasePath: /Ab9xQ/\n"
    monkeypatch.setattr(ctx.runner, "run",
                        lambda *a, **k: Result(0, sample, ""))
    port, base = c._read_panel_settings(2053)
    assert port == 2053
    assert base == "/Ab9xQ"   # normalised: leading slash, no trailing


def test_panel_settings_parse_root_base_path(ctx, monkeypatch):
    from shroud.proc import Result
    c = Xray3xuiComponent(ctx, _proto(ctx, "vless-reality-xhttp"))
    monkeypatch.setattr(ctx.runner, "run",
                        lambda *a, **k: Result(0, "port: 8443\nwebBasePath: /\n", ""))
    port, base = c._read_panel_settings(2053)
    assert port == 8443
    assert base == ""         # root => no suffix
