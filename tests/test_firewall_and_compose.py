from __future__ import annotations

import yaml

from shroud.phases import p2_firewall, p4_stack
from shroud import reality


def test_firewall_ports_exclude_panel(ctx):
    ports = p2_firewall.desired_ports(ctx)
    assert 443 in ports["tcp"]          # vless
    assert 8443 in ports["tcp"]         # telemt tcp
    assert 8443 in ports["udp"]         # hysteria udp
    assert 2096 in ports["tcp"]         # subscription
    assert 80 in ports["tcp"]           # nginx decoy
    assert 22 in ports["tcp"]           # ssh
    assert 2053 not in ports["tcp"]     # panel loopback only


def test_firewall_keeps_22_when_port_changed(ctx):
    ctx.ssh_port = 2222
    ports = p2_firewall.desired_ports(ctx)
    assert 2222 in ports["tcp"]
    assert 22 in ports["tcp"]           # no lock-out


def test_firewall_ruleset_drops_icmp_echo(ctx):
    rules = p2_firewall.render_ruleset(ctx)
    assert "icmp type echo-request drop" in rules
    assert "policy drop;" in rules
    assert "ct state established,related accept" in rules


def test_firewall_has_no_forward_chain(ctx):
    # A default-deny FORWARD chain blocks Docker-published container ports
    # (they traverse the forward hook). Docker must own forwarding.
    rules = p2_firewall.render_ruleset(ctx)
    assert "hook forward" not in rules
    assert "chain forward" not in rules
    # INPUT must still default-deny the host and open the published ports so the
    # userland-proxy path (traffic hitting INPUT) also works.
    assert "hook input" in rules
    assert "443" in rules and "8443" in rules


def test_compose_renders_all_services(ctx, monkeypatch):
    monkeypatch.setattr(reality, "generate_keypair", lambda c: ("PRIV", "PUB"))
    comps = p4_stack.build_components(ctx)
    for c in comps:
        c.prepare_secrets()
    compose = p4_stack.render_compose(ctx, comps)
    services = compose["services"]
    assert {"3xui", "hysteria2", "telemt", "nginx"}.issubset(services)
    # round-trips as valid YAML
    text = yaml.safe_dump(compose)
    assert yaml.safe_load(text) == compose


def test_compose_panel_bound_loopback(ctx, monkeypatch):
    monkeypatch.setattr(reality, "generate_keypair", lambda c: ("PRIV", "PUB"))
    comps = p4_stack.build_components(ctx)
    for c in comps:
        c.prepare_secrets()
    compose = p4_stack.render_compose(ctx, comps)
    panel_ports = compose["services"]["3xui"]["ports"]
    assert any(p.startswith("127.0.0.1:2053:") for p in panel_ports)
    assert all(not p.startswith("0.0.0.0:2053") and p != "2053:2053"
               for p in panel_ports)


def test_images_are_pinned(ctx, monkeypatch):
    monkeypatch.setattr(reality, "generate_keypair", lambda c: ("PRIV", "PUB"))
    comps = p4_stack.build_components(ctx)
    for c in comps:
        c.prepare_secrets()
    compose = p4_stack.render_compose(ctx, comps)
    for name, svc in compose["services"].items():
        assert ":" in svc["image"], f"{name} image not pinned to a tag"
