from __future__ import annotations

import pytest

from shroud import profile as profile_mod


def test_default_profile_loads_and_validates():
    prof = profile_mod.load(None)
    assert prof.version == "v1"
    ids = [p["id"] for p in prof.enabled_protocols()]
    assert "vless-reality-xhttp" in ids
    assert "hysteria2" in ids
    assert "telemt-mtproto" in ids
    # ws+cdn is disabled by default (needs a domain).
    assert prof.protocol("vless-ws-cdn")["enabled"] is False


def test_reality_xhttp_flow_must_be_empty():
    # Verified upstream: xtls-rprx-vision is invalid on xhttp; flow must be empty.
    prof = profile_mod.load(None)
    reality = prof.protocol("vless-reality-xhttp")
    assert reality["flow"] == ""
    assert reality["transport"] == "xhttp"


def test_sni_fallback_never_microsoft():
    prof = profile_mod.load(None)
    reality = prof.protocol("vless-reality-xhttp")
    assert all("microsoft.com" not in d for d in reality["sni_fallback"])


def test_image_ref_with_digest():
    prof = profile_mod.load(None)
    ref = prof.image_ref("xray_3xui")
    assert ref.startswith("ghcr.io/mhsanaei/3x-ui:v3.4.1@sha256:")


def test_panel_is_loopback_only():
    prof = profile_mod.load(None)
    assert prof.panel["bind"] == "127.0.0.1"
    assert prof.panel["access"] == "ssh-forward"


def test_invalid_profile_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("version: v1\nimages: {}\n", "utf-8")  # no protocols
    with pytest.raises(profile_mod.ProfileError):
        profile_mod.load(bad)


def test_unknown_protocol_type_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "version: v1\n"
        "images:\n  x: {repo: a, tag: b}\n"
        "panel: {bind: 127.0.0.1, access: ssh-forward}\n"
        "decoy: {mode: real-site}\n"
        "protocols:\n  - {id: x, enabled: true, type: bogus}\n",
        "utf-8")
    with pytest.raises(Exception):
        profile_mod.load(bad)
