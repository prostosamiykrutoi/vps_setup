from __future__ import annotations

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
