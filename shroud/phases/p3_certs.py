"""Phase 3 — Panel certificate (non-critical).

Reality needs NO real cert (it borrows the donor handshake). A cert is only for
safe panel login. Default: self-signed for the server IP, written into the certs
dir bind-mounted into the panel/hysteria containers. On failure the panel still
works over the loopback-forwarded HTTP, so this step never aborts.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .. import paths
from ..reconcile import Step

if TYPE_CHECKING:
    from ..context import Context


def certs_dir(ctx: "Context") -> Path:
    return paths.runtime_dir() / "certs"


class PanelCertStep(Step):
    id = "certs.panel_selfsigned"
    critical = False

    def inputs(self):
        return {"ip": self.ctx.facts.public_ip4}

    def check(self) -> bool:
        d = certs_dir(self.ctx)
        return (d / "fullchain.pem").exists() and (d / "privkey.pem").exists()

    def apply(self) -> None:
        ctx = self.ctx
        d = certs_dir(ctx)
        d.mkdir(parents=True, exist_ok=True)
        cn = ctx.facts.public_ip4 or "shroud.local"
        ctx.runner.run([
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-days", "3650",
            "-keyout", str(d / "privkey.pem"),
            "-out", str(d / "fullchain.pem"),
            "-subj", f"/CN={cn}",
        ])
        for f in ("privkey.pem", "fullchain.pem"):
            p = d / f
            if p.exists():
                p.chmod(0o600)
        ctx.summary["panel_cert"] = "self-signed (10y)"

    def verify(self) -> bool:
        return self.check() or self.ctx.dry_run


def steps(ctx: "Context") -> list[Step]:
    return [PanelCertStep(ctx)]
