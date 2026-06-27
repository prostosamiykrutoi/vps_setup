"""Cascade support (spec §10): exit emits a connect-info bundle; entry consumes
it and routes its xray outbound into the exit's VLESS-Reality.

The bundle is a versioned JSON artifact carrying ONLY client connection params
(address, Reality pbk/shortId/SNI, a cascade UUID) — never panel admin creds.
"""
from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import Context

BUNDLE_VERSION = 1


def build_bundle(ctx: "Context") -> dict:
    st = ctx.state
    proto = ctx.profile.protocol("vless-reality-xhttp") or {}
    return {
        "bundle_version": BUNDLE_VERSION,
        "address": ctx.facts.public_ip4,
        "port": int(proto.get("port", 443)),
        "protocol": "vless-reality-xhttp",
        "uuid": st.get_ref("vless_uuid"),
        "reality": {
            "public_key": st.get_ref("reality_pbk"),
            "short_id": st.get_ref("reality_short_id"),
            "sni": st.get_ref("reality_sni"),
            "fingerprint": proto.get("fingerprint", "chrome"),
        },
        "transport": {
            "network": "xhttp",
            "path": proto.get("xhttp_path", "/"),
            "mode": proto.get("xhttp_mode", "auto"),
        },
    }


def write_bundle(ctx: "Context", path: Path) -> str:
    """Write the bundle as JSON and also return a single-line shareable token."""
    bundle = build_bundle(ctx)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), "utf-8")
    path.chmod(0o600)
    token = "shroud-exit://" + base64.urlsafe_b64encode(
        json.dumps(bundle, separators=(",", ":")).encode()).decode()
    return token


def load_bundle(source: str) -> dict:
    """Load a bundle from a file path, URL, or shroud-exit:// token."""
    if source.startswith("shroud-exit://"):
        raw = base64.urlsafe_b64decode(source[len("shroud-exit://"):].encode())
        return json.loads(raw.decode())
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=20) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    return json.loads(Path(source).read_text("utf-8"))


def entry_outbound_config(bundle: dict) -> dict:
    """Build the xray outbound (on entry) that dials the exit's VLESS-Reality."""
    r = bundle.get("reality", {})
    t = bundle.get("transport", {})
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": bundle["address"],
                "port": bundle["port"],
                "users": [{
                    "id": bundle["uuid"],
                    "encryption": "none",
                    "flow": "",          # xhttp => no vision flow
                }],
            }],
        },
        "streamSettings": {
            "network": t.get("network", "xhttp"),
            "security": "reality",
            "xhttpSettings": {"path": t.get("path", "/"), "mode": t.get("mode", "auto")},
            "realitySettings": {
                "serverName": r.get("sni"),
                "publicKey": r.get("public_key"),
                "shortId": r.get("short_id"),
                "fingerprint": r.get("fingerprint", "chrome"),
            },
        },
        "tag": "cascade-exit",
    }
