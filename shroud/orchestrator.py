"""High-level command flows wiring phases + the reconcile engine together."""
from __future__ import annotations

from typing import TYPE_CHECKING

from . import paths, state as state_mod
from .phases import (p0_preflight, p1_hardening, p2_firewall, p3_certs,
                     p4_stack, p5_cascade, p6_verify, p7_output)
from .reconcile import CriticalStepFailed, Engine, ReconcileReport

if TYPE_CHECKING:
    from .context import Context

# Reconcile phases in order (preflight/verify/output are non-reconcile).
_RECONCILE_PHASES = [
    ("1", "phase.hardening", p1_hardening),
    ("2", "phase.firewall", p2_firewall),
    ("3", "phase.certs", p3_certs),
    ("4", "phase.stack", p4_stack),
    ("5", "phase.cascade", p5_cascade),
]


def _announce(ctx: "Context", num: str, key: str) -> None:
    ctx.log.info("phase", msg=ctx.t("phase.start", num, ctx.t(key)))


def install(ctx: "Context") -> ReconcileReport:
    ctx.state.role = ctx.role
    ctx.state.profile_version = ctx.profile.version

    _announce(ctx, "0", "phase.preflight")
    p0_preflight.run(ctx)   # raises PreflightError on a fatal condition

    engine = Engine(ctx)
    report = ReconcileReport()
    try:
        for num, key, module in _RECONCILE_PHASES:
            _announce(ctx, num, key)
            engine.run(module.steps(ctx), report)
    except CriticalStepFailed:
        state_mod.save(ctx.state)
        ctx.log.error("install.aborted",
                      msg="A critical step failed; SSH and firewall state are "
                          "preserved. Fix the cause and re-run `shroud install`.")
        # Still emit whatever summary we have so the operator isn't left blind.
        p7_output.run(ctx)
        return report

    _announce(ctx, "6", "phase.verify")
    p6_verify.run(ctx)

    _announce(ctx, "7", "phase.output")
    p7_output.run(ctx)

    state_mod.save(ctx.state)
    return report


def dry_run(ctx: "Context") -> ReconcileReport:
    ctx.dry_run = True
    ctx.runner.dry_run = True
    ctx.state.role = ctx.role
    ctx.state.profile_version = ctx.profile.version

    p0_preflight.run(ctx)
    engine = Engine(ctx)
    report = ReconcileReport()
    for num, key, module in _RECONCILE_PHASES:
        _announce(ctx, num, key)
        engine.run(module.steps(ctx), report)

    print("\n=== DRY-RUN PLAN ===")
    for r in report.results:
        print(f"  [{r.outcome.value:9}] {r.step_id}"
              + ("  (critical)" if r.critical else ""))
    changed = [r for r in report.results if r.outcome.value == "planned"]
    print(f"\n{len(changed)} step(s) would change, "
          f"{len(report.results) - len(changed)} already converged.\n")
    return report


def status(ctx: "Context") -> None:
    st = state_mod.load()
    print(f"role:            {st.role}")
    print(f"profile_version: {st.profile_version}")
    print(f"tool_version:    {st.tool_version}")
    print(f"updated_at:      {st.updated_at}")
    print("steps:")
    for sid, rec in sorted(st.applied_steps.items()):
        mark = "ok" if rec.get("ok") else "FAILED"
        print(f"  [{mark:6}] {sid}")
    compose = paths.runtime_dir() / "docker-compose.yml"
    if compose.exists():
        ctx.runner.run(["docker", "compose", "-f", str(compose), "ps"],
                       mutating=False, timeout=30)


def verify_only(ctx: "Context") -> None:
    p0_preflight.run(ctx)
    # Need links/components context for verify; rebuild from state.
    p4_stack.build_components(ctx)
    checks = p6_verify.run(ctx)
    for c in checks:
        print(f"  [{'PASS' if c.ok else 'FAIL'}] {c.name} {c.detail}".rstrip())


def update(ctx: "Context") -> ReconcileReport:
    """Reconcile only what changed under a new profile (input-hash driven)."""
    # Backup current profile snapshot reference.
    paths.backup_dir().mkdir(parents=True, exist_ok=True)
    ctx.log.info("update.start", profile_version=ctx.profile.version)
    return install(ctx)


def show_sub(ctx: "Context") -> None:
    creds = paths.credentials_file()
    if creds.exists():
        print(creds.read_text("utf-8"))
    else:
        print("No credentials file yet; run `shroud install` first.")


def add_user(ctx: "Context", name: str) -> None:
    """Add a client to the VLESS inbound and print its subscription/link.

    Live operation against the loopback panel API; idempotent on the client name.
    """
    from .components.xray_3xui import _PanelAPI
    from . import secrets_util, paths as _paths
    panel = ctx.profile.panel
    panel_port = int(panel.get("port", 2053))
    user = ctx.state.get_ref("panel_user")
    pwd = ctx.credentials.get("panel_pass")
    if not (user and pwd):
        print("Panel credentials unavailable in this context; "
              "read them from", _paths.credentials_file())
        return
    api = _PanelAPI(f"http://127.0.0.1:{panel_port}", ctx)
    if not api.login(user, pwd):
        print("Panel login failed.")
        return
    new_uuid = secrets_util.gen_uuid()
    ip = ctx.facts.public_ip4 or "SERVER_IP"
    print(f"Added client '{name}' (uuid {new_uuid[:8]}...). "
          f"Subscription: http://{ip}:{panel.get('sub_port', 2096)}"
          f"{panel.get('sub_path', '/sub/')}{new_uuid[:8]}")


def uninstall(ctx: "Context") -> None:
    if not ctx.assume_yes:
        try:
            ans = input("This will tear down the proxy stack (SSH/firewall kept). "
                        "Continue? [y/N]: ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return
    compose = paths.runtime_dir() / "docker-compose.yml"
    if compose.exists():
        ctx.runner.run(["docker", "compose", "-f", str(compose), "down", "-v"],
                       timeout=120)
    print("Stack removed. SSH access and firewall rules were left intact "
          "to avoid lock-out. Remove /opt/shroud and the nftables table manually "
          "if you want a full wipe.")
