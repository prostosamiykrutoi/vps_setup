"""hysteria2 — QUIC proxy with masquerade-to-real-site (verified upstream).

Uses the panel's self-signed/IP cert for TLS; on an unauthenticated probe the
server reverse-proxies the masquerade site, so it looks like a plain web server.
"""
from __future__ import annotations

from pathlib import Path

from .. import render, secrets_util
from ..log import register_secret
from .base import Component


class Hysteria2Component(Component):
    type = "hysteria2"

    def prepare_secrets(self) -> None:
        ctx = self.ctx
        auth = ctx.state.get_ref("hysteria2_auth")
        if not auth:
            auth = secrets_util.gen_hysteria_auth()
            ctx.state.set_ref("hysteria2_auth", auth)
        register_secret(auth)
        self._auth = auth
        ctx.credentials["hysteria2_auth"] = auth

    @property
    def masquerade_url(self) -> str:
        return self.proto.get("masquerade", {}).get("url", "https://news.ycombinator.com")

    def render(self, runtime_dir: Path) -> None:
        cfg_dir = runtime_dir / "hysteria2"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        text = render.render(
            "hysteria.yaml.j2",
            port=self.port,
            auth=self._auth,
            masquerade_url=self.masquerade_url,
        )
        cfg = cfg_dir / "config.yaml"
        cfg.write_text(text, "utf-8")
        cfg.chmod(0o600)

    def compose_service(self) -> tuple[str, dict]:
        svc = {
            "image": self._image("hysteria2"),
            "container_name": "shroud-hysteria2",
            "restart": "unless-stopped",
            "command": ["server", "-c", "/etc/hysteria/config.yaml"],
            "volumes": [
                "./hysteria2:/etc/hysteria:ro",
                "./certs:/certs:ro",
            ],
            "ports": [f"{self.port}:{self.port}/udp"],
        }
        return "hysteria2", svc

    def firewall_ports(self) -> list[tuple[int, str]]:
        return [(self.port, "udp")]

    def links(self) -> list[tuple[str, str]]:
        ip = self.ctx.facts.public_ip4 or "SERVER_IP"
        # hy2://<auth>@<host>:<port>?insecure=1 (self-signed/IP cert).
        return [("Hysteria2",
                 f"hy2://{self._auth}@{ip}:{self.port}?insecure=1#shroud-hy2")]
