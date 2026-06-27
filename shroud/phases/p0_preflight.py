"""Phase 0 — Preflight (critical).

Detect OS/arch, confirm root, check network, discover public IP + ASN, and warn
on known-throttling providers (D4). Populates ``ctx.facts``.
"""
from __future__ import annotations

import json
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context

# ASNs known to RST/throttle circumvention traffic (the "~16 KB then reset"
# behaviour). Non-exhaustive; the profile/operator can extend it.
THROTTLED_ASNS = {
    "24940": "Hetzner",
    "213230": "Hetzner",
    "14061": "DigitalOcean",
    "16276": "OVH",
    "35540": "OVH",
}


class PreflightError(RuntimeError):
    pass


def _read_os_release() -> dict:
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    info[k] = v.strip().strip('"')
    except OSError:
        pass
    return info


def _detect_arch(ctx: "Context") -> str:
    res = ctx.runner.run(["dpkg", "--print-architecture"], mutating=False)
    arch = res.stdout.strip() if res.ok else ""
    if not arch:
        import platform
        m = platform.machine()
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(m, m)
    return arch


def _http_json(url: str, timeout: int = 8) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _detect_ip_asn(ctx: "Context") -> None:
    facts = ctx.facts
    data = _http_json("https://ipinfo.io/json")
    if data:
        facts.public_ip4 = data.get("ip")
        org = data.get("org", "")  # e.g. "AS24940 Hetzner Online GmbH"
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            facts.asn = parts[0][2:]
            facts.asn_org = parts[1] if len(parts) > 1 else org
    if not facts.public_ip4:
        res = ctx.runner.run(["curl", "-4", "-s", "https://api.ipify.org"],
                             mutating=False, timeout=10)
        if res.ok:
            facts.public_ip4 = res.stdout.strip()


def run(ctx: "Context") -> None:
    facts = ctx.facts
    osr = _read_os_release()
    facts.os_id = osr.get("ID", "")
    facts.os_version = osr.get("VERSION_ID", "")
    facts.arch = _detect_arch(ctx)

    if facts.os_id != "ubuntu" or facts.os_version not in ("22.04", "24.04"):
        # Warn but allow other ubuntu; hard-fail non-ubuntu.
        if facts.os_id != "ubuntu":
            raise PreflightError(
                ctx.t("preflight.os_unsupported",
                      f"{facts.os_id} {facts.os_version}"))
        ctx.log.warn("preflight.untested_ubuntu", version=facts.os_version)

    # Network reachability (best-effort, non-fatal individually).
    for host in ("https://github.com", "https://ghcr.io"):
        res = ctx.runner.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                              "--max-time", "8", host], mutating=False, timeout=12)
        if not res.ok or res.stdout.strip().startswith(("0", "4", "5")):
            ctx.log.warn("preflight.network_check", host=host, code=res.stdout.strip())

    _detect_ip_asn(ctx)
    ctx.log.info("preflight",
                 msg=ctx.t("preflight.ip_detected", facts.public_ip4 or "?",
                           facts.asn or "?", facts.asn_org or "?"))

    if facts.asn in THROTTLED_ASNS:
        facts.throttled_asn = True
        ctx.log.warn("preflight",
                     msg=ctx.t("preflight.asn_throttle",
                               facts.asn_org or THROTTLED_ASNS[facts.asn],
                               facts.asn))
        if ctx.strict:
            raise PreflightError(ctx.t("preflight.strict_abort"))
