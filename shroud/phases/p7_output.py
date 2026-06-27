"""Phase 7 — Summary to screen + /root/shroud-credentials.txt (mode 0600)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .. import paths

if TYPE_CHECKING:
    from ..context import Context


def build_summary_text(ctx: "Context") -> str:
    panel = ctx.profile.panel
    panel_port = panel.get("port", 2053)
    ip = ctx.facts.public_ip4 or "SERVER_IP"
    L: list[str] = []
    L.append("=" * 60)
    L.append(ctx.t("summary.title"))
    L.append("=" * 60)
    L.append(f"ROLE: {ctx.role}")
    L.append(f"SSH port: {ctx.ssh_port}" +
             ("  (port 22 kept open until you verify; close it manually)"
              if ctx.ssh_port != 22 else ""))
    L.append("")
    L.append("3X-UI PANEL (loopback only):")
    L.append(f"  URL:   http://127.0.0.1:{panel_port}")
    L.append(f"  via:   ssh -L {panel_port}:127.0.0.1:{panel_port} root@{ip}")
    L.append(f"  user:  {ctx.credentials.get('panel_user', '?')}")
    L.append(f"  pass:  {ctx.credentials.get('panel_pass', '?')}")
    L.append("")
    L.append("PROTOCOLS:")
    if ctx.links:
        for label, uri in ctx.links:
            L.append(f"  {label}:")
            L.append(f"    {uri}")
    else:
        L.append("  (none — stack not provisioned in this run)")
    L.append("")
    if ctx.summary.get("subscription"):
        L.append(f"SUBSCRIPTION: {ctx.summary['subscription']}")
        L.append("")
    if ctx.role == "exit" and ctx.summary.get("connect_info_token"):
        L.append("CONNECT-INFO for entry node:")
        L.append(f"  file:  {ctx.summary.get('connect_info_file')}")
        L.append(f"  token: {ctx.summary['connect_info_token']}")
        L.append("")
    if ctx.role == "entry" and ctx.summary.get("cascade_exit"):
        L.append(f"CASCADE: routing through exit {ctx.summary['cascade_exit']}")
        L.append("")
    L.append(f"Panel certificate: {ctx.summary.get('panel_cert', 'self-signed')}")
    if ctx.facts.throttled_asn:
        L.append("")
        L.append(f"NOTE: provider ASN {ctx.facts.asn} is known to throttle "
                 "circumvention traffic; consider a different region.")
    if ctx.summary.get("verify"):
        L.append("")
        L.append("SELF-TEST:")
        for name, ok, detail in ctx.summary["verify"]:
            mark = "PASS" if ok else "FAIL"
            L.append(f"  [{mark}] {name} {detail}".rstrip())
    L.append("=" * 60)
    return "\n".join(L) + "\n"


def run(ctx: "Context") -> None:
    text = build_summary_text(ctx)
    # To screen.
    print("\n" + text)
    if ctx.dry_run:
        return
    # To credentials file (0600).
    creds = paths.credentials_file()
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text(text, "utf-8")
    creds.chmod(0o600)
    ctx.log.info("output", msg=ctx.t("output.saved", str(creds)))
