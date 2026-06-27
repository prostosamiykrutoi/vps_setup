"""nginx decoy — serves a plausible real site on a direct hit to the IP/panel.

The decoy content ships in the repo (``decoy/``) so a probe never sees a default
"Welcome to nginx" page (spec §9.4). Bound to loopback-facing 8080; the firewall
and the other listeners front it.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from .base import Component

_PKG_ROOT = Path(__file__).resolve().parent.parent.parent
_DECOY_SRC = _PKG_ROOT / "decoy"


class NginxDecoyComponent(Component):
    type = "nginx"

    def __init__(self, ctx, proto: dict | None = None):
        super().__init__(ctx, proto or {"id": "nginx-decoy", "port": 8080})

    @property
    def port(self) -> int:
        return 8080

    def render(self, runtime_dir: Path) -> None:
        from .. import render as render_mod
        cfg_dir = runtime_dir / "nginx"
        html_dir = cfg_dir / "html"
        html_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "default.conf").write_text(
            render_mod.render("nginx-decoy.conf.j2"), "utf-8")
        # Copy bundled decoy content.
        if _DECOY_SRC.exists():
            for item in _DECOY_SRC.iterdir():
                if item.is_file():
                    shutil.copy2(item, html_dir / item.name)

    def compose_service(self) -> tuple[str, dict]:
        svc = {
            "image": self._image("nginx"),
            "container_name": "shroud-nginx",
            "restart": "unless-stopped",
            "volumes": [
                "./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro",
                "./nginx/html:/usr/share/nginx/html:ro",
            ],
            "expose": ["8080"],
            "healthcheck": {
                "test": ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/healthz"],
                "interval": "30s",
                "timeout": "5s",
                "retries": 3,
            },
        }
        return "nginx", svc

    def firewall_ports(self) -> list[tuple[int, str]]:
        return []  # not directly exposed; fronted by other listeners
