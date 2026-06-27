"""telemt — MTProto proxy with FakeTLS + probe resistance (verified upstream).

Image runs distroless/non-root with cap_drop ALL + cap_add NET_BIND_SERVICE;
config is mounted as a directory at /etc/telemt and passed as the command arg.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .. import render, secrets_util
from ..log import register_secret
from .base import Component

if TYPE_CHECKING:
    pass


class TelemtComponent(Component):
    type = "telemt"

    def prepare_secrets(self) -> None:
        ctx = self.ctx
        secret = ctx.state.get_ref("telemt_secret")
        if not secret:
            secret = secrets_util.gen_mtproto_secret()
            ctx.state.set_ref("telemt_secret", secret)
        register_secret(secret)
        self._secret = secret
        self._user = ctx.state.get_ref("telemt_user") or "tg"
        ctx.state.set_ref("telemt_user", self._user)
        ctx.credentials["telemt_secret"] = secret

    @property
    def fake_tls_domain(self) -> str:
        d = self.proto.get("fake_tls_domain", "dl.google.com")
        if self.ctx.mode == "interactive":
            d = self.ctx.prompt("telemt fake_tls_domain", d)
        return d

    def render(self, runtime_dir: Path) -> None:
        cfg_dir = runtime_dir / "telemt"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        text = render.render(
            "telemt.toml.j2",
            port=self.port,
            fake_tls_domain=self.fake_tls_domain,
            unknown_sni_action=self.proto.get("unknown_sni_action", "reject_handshake"),
            user=self._user,
            secret=self._secret,
        )
        cfg = cfg_dir / "config.toml"
        cfg.write_text(text, "utf-8")
        cfg.chmod(0o600)

    def compose_service(self) -> tuple[str, dict]:
        svc = {
            "image": self._image("telemt"),
            "container_name": "shroud-telemt",
            "restart": "unless-stopped",
            "command": ["/etc/telemt/config.toml"],
            "volumes": ["./telemt:/etc/telemt:ro"],
            "ports": [f"{self.port}:{self.port}"],
            "cap_drop": ["ALL"],
            "cap_add": ["NET_BIND_SERVICE"],
            "read_only": True,
        }
        return "telemt", svc

    def links(self) -> list[tuple[str, str]]:
        ip = self.ctx.facts.public_ip4 or "SERVER_IP"
        # FakeTLS "ee" link: ee + 16-byte secret hex + hex(SNI domain).
        ee = "ee" + self._secret + self.fake_tls_domain.encode("utf-8").hex()
        return [("Telegram (MTProto)",
                 f"tg://proxy?server={ip}&port={self.port}&secret={ee}")]
