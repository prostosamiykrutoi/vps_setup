"""Phase 4 — Proxy stack (Docker Compose).

Builds components from the profile, prepares their secrets, renders configs +
``docker-compose.yml``, brings the stack up, then provisions the panel inbound.
Per-component failures are non-fatal: the rest of the stack still comes up and a
partial result is reported (spec §7 Phase 4).
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .. import paths
from ..components import registry
from ..components.nginx import NginxDecoyComponent
from ..components.xray_3xui import Xray3xuiComponent
from ..reconcile import Step

if TYPE_CHECKING:
    from ..context import Context


def build_components(ctx: "Context") -> list:
    if ctx.components:
        return ctx.components
    comps = registry.build_enabled(ctx)
    comps.append(NginxDecoyComponent(ctx))   # decoy always present
    ctx.components = comps
    return comps


def render_compose(ctx: "Context", components: list) -> dict:
    services: dict[str, dict] = {}
    for comp in components:
        svc = comp.compose_service()
        if svc is not None:
            name, definition = svc
            services[name] = definition
    return {"services": services}


def _write_stack(ctx: "Context", components: list) -> Path:
    rt = paths.runtime_dir()
    rt.mkdir(parents=True, exist_ok=True)
    # Root-only dir: component configs inside carry secrets and some must be
    # world-readable for non-root containers, so the dir itself gates host access.
    try:
        rt.chmod(0o700)
    except OSError:
        pass
    for comp in components:
        comp.render(rt)
    compose = render_compose(ctx, components)
    compose_path = rt / "docker-compose.yml"
    compose_path.write_text(yaml.safe_dump(compose, sort_keys=False), "utf-8")
    return compose_path


class StackStep(Step):
    id = "stack.compose_up"
    critical = False

    def inputs(self):
        return {
            "protocols": [p.get("id") for p in self.ctx.enabled_protocols()],
            "profile_version": self.ctx.profile.version,
        }

    def check(self) -> bool:
        # Converged iff compose file matches desired AND all services are running.
        components = build_components(self.ctx)
        rt = paths.runtime_dir()
        compose_path = rt / "docker-compose.yml"
        if not compose_path.exists():
            return False
        import yaml as _yaml
        try:
            current = _yaml.safe_load(compose_path.read_text("utf-8"))
        except Exception:
            return False
        if current != render_compose(self.ctx, components):
            return False
        if self.ctx.dry_run:
            return True
        res = self.ctx.runner.run(
            ["docker", "compose", "-f", str(compose_path), "ps",
             "--status", "running", "--format", "{{.Service}}"],
            mutating=False, timeout=30)
        running = set(res.stdout.split())
        want = {name for name, _ in
                (c.compose_service() or (None, None) for c in components)
                if name}
        return want.issubset(running)

    def apply(self) -> None:
        ctx = self.ctx
        components = build_components(ctx)
        for comp in components:
            try:
                comp.prepare_secrets()
            except Exception as exc:
                ctx.log.error("stack.secret_error", comp=comp.id, error=str(exc))
        compose_path = _write_stack(ctx, components)
        ctx.runner.run(["docker", "compose", "-f", str(compose_path),
                        "pull", "--quiet"], timeout=600)
        ctx.runner.run(["docker", "compose", "-f", str(compose_path),
                        "up", "-d", "--remove-orphans"], timeout=600)
        # Provision panel inbound (3x-ui) after the stack is up.
        for comp in components:
            if isinstance(comp, Xray3xuiComponent):
                try:
                    comp.provision()
                except Exception as exc:
                    ctx.log.error("stack.provision_error", error=str(exc))
        self._collect_links(components)

    def verify(self) -> bool:
        if self.ctx.dry_run:
            self._collect_links(build_components(self.ctx))
            return True
        compose_path = paths.runtime_dir() / "docker-compose.yml"
        res = self.ctx.runner.run(
            ["docker", "compose", "-f", str(compose_path), "ps",
             "--format", "{{.Service}}"], mutating=False, timeout=30)
        # At least one service up => partial success is acceptable (non-critical).
        return bool(res.stdout.strip()) or self.ctx.dry_run

    def _collect_links(self, components: list) -> None:
        ctx = self.ctx
        ctx.links = []
        for comp in components:
            try:
                ctx.links.extend(comp.links())
            except Exception as exc:
                ctx.log.warn("stack.link_error", comp=comp.id, error=str(exc))
        # Subscription URL (3x-ui subscription server).
        panel = ctx.profile.panel
        ip = ctx.facts.public_ip4 or "SERVER_IP"
        sub_port = panel.get("sub_port", 2096)
        sub_path = panel.get("sub_path", "/sub/")
        sub_id = ctx.state.get_ref("reality_sub_id", "")
        if sub_id:
            ctx.summary["subscription"] = f"http://{ip}:{sub_port}{sub_path}{sub_id}"


def steps(ctx: "Context") -> list[Step]:
    return [StackStep(ctx)]
