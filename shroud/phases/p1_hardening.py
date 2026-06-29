"""Phase 1 — Host hardening (native).

Steps: sysctl network hardening (critical), fail2ban for sshd (critical), and a
lock-out-SAFE SSH port change (non-critical). ICMP echo-request is dropped in the
firewall ruleset (Phase 2) since we use nftables.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..reconcile import Step

if TYPE_CHECKING:
    from ..context import Context

SYSCTL_FILE = "/etc/sysctl.d/99-shroud.conf"
SYSCTL_SETTINGS = {
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
}


def _root(ctx: "Context") -> Path:
    import os
    return Path(os.environ.get("SHROUD_ROOT", "/"))


class SysctlStep(Step):
    id = "hardening.sysctl"
    critical = True

    def inputs(self):
        return SYSCTL_SETTINGS

    def _path(self) -> Path:
        return _root(self.ctx) / SYSCTL_FILE.lstrip("/")

    def _desired(self) -> str:
        lines = ["# Managed by shroud. Do not edit."]
        lines += [f"{k} = {v}" for k, v in SYSCTL_SETTINGS.items()]
        return "\n".join(lines) + "\n"

    def check(self) -> bool:
        p = self._path()
        return p.exists() and p.read_text("utf-8") == self._desired()

    def apply(self) -> None:
        p = self._path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self._desired(), "utf-8")
        self.ctx.runner.run(["sysctl", "--system"])

    def verify(self) -> bool:
        return self._path().exists()


class Fail2banStep(Step):
    id = "hardening.fail2ban"
    critical = True

    def inputs(self):
        return {"ssh_port": self.ctx.ssh_port}

    def _jail(self) -> Path:
        return _root(self.ctx) / "etc/fail2ban/jail.local"

    def _desired(self) -> str:
        return (
            "# Managed by shroud.\n"
            "[sshd]\n"
            "enabled  = true\n"
            f"port     = {self.ctx.ssh_port}\n"
            "maxretry = 5\n"
            "bantime  = 3600\n"
            "findtime = 600\n"
            "bantime.increment = true\n"
            "bantime.factor    = 2\n"
            "bantime.maxtime   = 604800\n"
        )

    def check(self) -> bool:
        p = self._jail()
        if not (p.exists() and p.read_text("utf-8") == self._desired()):
            return False
        # Also ensure the service is active.
        res = self.ctx.runner.run(["systemctl", "is-active", "fail2ban"],
                                  mutating=False)
        return res.stdout.strip() == "active"

    def apply(self) -> None:
        ctx = self.ctx
        if not ctx.runner.have("fail2ban-server"):
            ctx.runner.run(["apt-get", "-o", "DPkg::Lock::Timeout=600",
                            "install", "-y", "-qq", "fail2ban"], timeout=600)
        p = self._jail()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self._desired(), "utf-8")
        ctx.runner.run(["systemctl", "enable", "fail2ban"])
        ctx.runner.run(["systemctl", "restart", "fail2ban"])

    def verify(self) -> bool:
        res = self.ctx.runner.run(["systemctl", "is-active", "fail2ban"],
                                  mutating=False)
        return res.stdout.strip() == "active" or self.ctx.dry_run


class SshPortStep(Step):
    """Change SSH port WITHOUT risking lock-out.

    We keep port 22 listening alongside the new port and verify sshd is actually
    bound to the new port before declaring success. The firewall (Phase 2) keeps
    both ports open; the operator closes 22 manually after confirming.
    """
    id = "hardening.ssh_port"
    critical = False

    def inputs(self):
        return {"ssh_port": self.ctx.ssh_port}

    def applicable(self) -> bool:
        return self.ctx.ssh_port != 22

    def _config(self) -> Path:
        return _root(self.ctx) / "etc/ssh/sshd_config"

    def check(self) -> bool:
        p = self._config()
        if not p.exists():
            return False
        text = p.read_text("utf-8")
        return bool(re.search(rf"(?m)^Port {self.ctx.ssh_port}\b", text))

    def apply(self) -> None:
        ctx = self.ctx
        p = self._config()
        text = p.read_text("utf-8") if p.exists() else ""
        # Ensure both 22 and the new port are present (no lock-out).
        if not re.search(r"(?m)^Port 22\b", text):
            text += "\nPort 22\n"
        if not re.search(rf"(?m)^Port {ctx.ssh_port}\b", text):
            text += f"Port {ctx.ssh_port}\n"
        p.write_text(text, "utf-8")
        ctx.log.warn("ssh", msg=ctx.t("ssh.warn_session"))
        ctx.runner.run(["systemctl", "restart", "ssh"])

    def verify(self) -> bool:
        ctx = self.ctx
        if ctx.dry_run:
            return True
        res = ctx.runner.run(["ss", "-tlnH"], mutating=False)
        listening = f":{ctx.ssh_port}" in res.stdout
        if listening:
            ctx.log.info("ssh", msg=ctx.t("ssh.selftest_ok", ctx.ssh_port))
            return True
        ctx.log.warn("ssh", msg=ctx.t("ssh.selftest_fail", ctx.ssh_port, 22))
        return False

    def rollback(self) -> None:
        ctx = self.ctx
        p = self._config()
        if not p.exists():
            return
        text = p.read_text("utf-8")
        text = re.sub(rf"(?m)^Port {ctx.ssh_port}\b.*\n?", "", text)
        p.write_text(text, "utf-8")
        ctx.runner.run(["systemctl", "restart", "ssh"])
        ctx.ssh_port = 22  # fall back so the firewall keeps 22 open


def steps(ctx: "Context") -> list[Step]:
    return [SysctlStep(ctx), Fail2banStep(ctx), SshPortStep(ctx)]
