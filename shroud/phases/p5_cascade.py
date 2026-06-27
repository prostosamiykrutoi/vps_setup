"""Phase 5 — Cascade wiring (spec §10).

* role=standalone: skipped.
* role=exit: emit the connect-info bundle (+ token) for entry nodes.
* role=entry: consume the exit bundle and wire xray's outbound into the exit.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .. import cascade, paths
from ..reconcile import Step

if TYPE_CHECKING:
    from ..context import Context


class ExitBundleStep(Step):
    id = "cascade.exit_bundle"
    critical = False

    def applicable(self) -> bool:
        return self.ctx.role == "exit"

    def inputs(self):
        return {"uuid": self.ctx.state.get_ref("vless_uuid")}

    def check(self) -> bool:
        return paths.connect_info_file().exists()

    def apply(self) -> None:
        token = cascade.write_bundle(self.ctx, paths.connect_info_file())
        self.ctx.summary["connect_info_file"] = str(paths.connect_info_file())
        self.ctx.summary["connect_info_token"] = token

    def verify(self) -> bool:
        return self.check() or self.ctx.dry_run


class EntryWireStep(Step):
    id = "cascade.entry_wire"
    critical = False

    def applicable(self) -> bool:
        return self.ctx.role == "entry"

    def inputs(self):
        return {"exit": self.ctx.exit_bundle}

    def check(self) -> bool:
        # Converged if the entry outbound config has been materialised.
        return (paths.runtime_dir() / "entry" / "outbound.json").exists()

    def apply(self) -> None:
        ctx = self.ctx
        if not ctx.exit_bundle:
            raise RuntimeError("role=entry requires --exit <bundle|token|url>")
        bundle = cascade.load_bundle(ctx.exit_bundle)
        outbound = cascade.entry_outbound_config(bundle)
        import json
        d = paths.runtime_dir() / "entry"
        d.mkdir(parents=True, exist_ok=True)
        (d / "outbound.json").write_text(json.dumps(outbound, indent=2), "utf-8")
        ctx.summary["cascade_exit"] = bundle.get("address")
        # NB: the entry's local xray inbound -> this outbound is rendered into the
        # 3x-ui xray config; here we persist the resolved outbound for the panel
        # to adopt and for `verify` to exercise end-to-end.

    def verify(self) -> bool:
        return self.check() or self.ctx.dry_run


def steps(ctx: "Context") -> list[Step]:
    return [ExitBundleStep(ctx), EntryWireStep(ctx)]
