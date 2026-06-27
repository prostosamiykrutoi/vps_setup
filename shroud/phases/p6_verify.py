"""Phase 6 — Verification / self-test (informational; never fatal)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .. import verify

if TYPE_CHECKING:
    from ..context import Context


def run(ctx: "Context") -> list:
    if ctx.dry_run:
        return []
    checks = verify.run_all(ctx)
    ctx.summary["verify"] = [(c.name, c.ok, c.detail) for c in checks]
    for c in checks:
        key = "verify.pass" if c.ok else "verify.fail"
        ctx.log.info("verify", msg=ctx.t(key, f"{c.name} {c.detail}".strip()))
    ctx.log.info("verify", msg=ctx.t("verify.note"))
    return checks
