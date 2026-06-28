#!/usr/bin/env python3
"""CI integration driver — exercises the REAL proxy stack on a GitHub runner.

It deliberately runs ONLY the parts that are safe + meaningful in CI:
  preflight -> certs -> proxy stack (real image pulls, `docker compose up`,
  3x-ui panel provisioning + inbound creation) -> self-tests.

It SKIPS host hardening and the nftables firewall on purpose: a host-wide
default-deny policy or systemd/sshd changes could sever the runner's own
connectivity. Those are validated on a real VPS, not in CI.

Exit non-zero if the stack does not come up or the VLESS inbound is not created
via the panel API — those are the volatile, most-likely-to-break integrations we
want CI to catch.
"""
from __future__ import annotations

import os
import subprocess
import sys

os.environ.setdefault("SHROUD_ROOT", "/")

from shroud import profile as pm                      # noqa: E402
from shroud.context import Context                    # noqa: E402
from shroud.state import State                        # noqa: E402
from shroud.reconcile import Engine                   # noqa: E402
from shroud.phases import p0_preflight, p3_certs, p4_stack, p6_verify, p7_output  # noqa: E402
from shroud.components.xray_3xui import Xray3xuiComponent, _PanelAPI  # noqa: E402
from shroud import paths                              # noqa: E402

COMPOSE = "/opt/shroud/runtime/docker-compose.yml"
EXPECTED = {"shroud-3xui", "shroud-hysteria2", "shroud-telemt", "shroud-nginx"}


def _container_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _dump_logs() -> None:
    for name in sorted(EXPECTED):
        print(f"\n===== docker logs {name} (tail) =====")
        subprocess.run(["docker", "logs", "--tail", "40", name])


def main() -> int:
    ctx = Context(role="standalone", mode="quick", lang="en",
                  profile=pm.load(None), state=State())
    try:
        p0_preflight.run(ctx)
    except Exception as exc:           # OS gate etc. — log, keep going in CI
        print(f"[preflight] {exc}")
    # In CI the runner's public IP is not hairpinned back to itself, so the
    # handshake/decoy self-tests must target loopback to exercise the real local
    # stack (published ports bind 0.0.0.0, reachable via 127.0.0.1).
    ctx.facts.public_ip4 = "127.0.0.1"
    print(f"[ci] ip={ctx.facts.public_ip4} arch={ctx.facts.arch}")

    engine = Engine(ctx)
    engine.run(p3_certs.steps(ctx))
    engine.run(p4_stack.steps(ctx))

    failures: list[str] = []

    # 1. Containers up?
    for name in sorted(EXPECTED):
        up = _container_running(name)
        print(f"[ci] container {name}: {'running' if up else 'NOT running'}")
        if not up:
            failures.append(f"{name} not running")

    # 2. Inbound actually created via the panel API?
    panel_port = int(ctx.profile.panel.get("port", 2053))
    api = _PanelAPI(f"http://127.0.0.1:{panel_port}", ctx)
    user = ctx.credentials.get("panel_user")
    pwd = ctx.credentials.get("panel_pass")
    if user and pwd and api.login(user, pwd):
        if api.inbound_exists("shroud-vless-reality"):
            print("[ci] VLESS inbound present via API: OK")
        else:
            failures.append("VLESS inbound missing via API")
            print("[ci] VLESS inbound MISSING via API")
    else:
        failures.append("panel API login failed")
        print("[ci] panel API login FAILED")

    # 3. Self-tests (informational — printed, not fatal).
    checks = p6_verify.run(ctx)
    print("\n[ci] self-test results:")
    for c in checks:
        print(f"    [{'PASS' if c.ok else 'FAIL'}] {c.name} {c.detail}".rstrip())

    print()
    print(p7_output.build_summary_text(ctx))

    if failures:
        print("\n[ci] FAILURES:", "; ".join(failures))
        _dump_logs()
    # Teardown so reruns are clean.
    subprocess.run(["docker", "compose", "-f", COMPOSE, "down", "-v"])
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
