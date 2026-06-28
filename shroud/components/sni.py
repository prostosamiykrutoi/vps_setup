"""Reality donor-SNI selection via XTLS/RealiTLScanner (verified v0.2.3).

Strategy (spec §9.1): scan the server's OWN subnet/ASN for a reachable TLS-1.3
donor in the same CIDR (co-location => no instant giveaway). Fall back to a
same-ASN/last-resort donor from the profile — never ``www.microsoft.com``.

RealiTLScanner CLI (verified): ``-addr`` accepts a CIDR, ``-port`` (def 443),
``-thread``, ``-out`` CSV. Column order has varied across releases, so we never
trust a fixed index: we scan every cell of every row and pick the first value
that is a *syntactically valid domain* (rejects junk like ``TLS 1.3``).
Assets: ``RealiTLScanner-linux-amd64`` / ``-linux-arm64``.
"""
from __future__ import annotations

import ipaddress
import re
import tempfile
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from .. import paths

if TYPE_CHECKING:
    from ..context import Context

_REPO = "XTLS/RealiTLScanner"
_PINNED_TAG = "v0.2.3"

# A valid hostname: labels of [a-z0-9-], a real alphabetic TLD (>=2). This
# rejects "TLS 1.3" (space + numeric TLD), IPs, and other non-domain cells.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$")


def is_valid_domain(s: str) -> bool:
    s = (s or "").strip().lstrip("*.")
    return bool(_DOMAIN_RE.match(s)) and "microsoft.com" not in s


def _asset_for_arch(arch: str) -> str:
    a = "arm64" if arch in ("arm64", "aarch64") else "amd64"
    return f"RealiTLScanner-linux-{a}"


def _server_cidr(ip: str, bits: int = 24) -> str | None:
    try:
        net = ipaddress.ip_network(f"{ip}/{bits}", strict=False)
        return str(net)
    except ValueError:
        return None


def select_donor(ctx: "Context") -> str:
    """Return a donor SNI: same-ASN scan result, else a validated fallback."""
    proto = ctx.profile.protocol("vless-reality-xhttp") or {}
    fallbacks = [d for d in proto.get("sni_fallback", []) if is_valid_domain(d)]
    fallback = fallbacks[0] if fallbacks else "dl.google.com"

    if proto.get("sni_strategy") != "same-asn-scan":
        static = proto.get("static_sni", fallback)
        return static if is_valid_domain(static) else fallback

    ctx.log.info("sni", msg=ctx.t("sni.scanning"))
    ip = ctx.facts.public_ip4
    cidr = _server_cidr(ip) if ip else None
    if not cidr:
        ctx.log.warn("sni", msg=ctx.t("sni.fallback", fallback))
        return fallback

    binary = _download_scanner(ctx)
    if binary is None:
        ctx.log.warn("sni", msg=ctx.t("sni.fallback", fallback))
        return fallback

    donor = _run_scan(ctx, binary, cidr)
    if donor and is_valid_domain(donor):
        ctx.log.info("sni", msg=ctx.t("sni.found", donor))
        return donor

    ctx.log.warn("sni", msg=ctx.t("sni.fallback", fallback))
    return fallback


def _download_scanner(ctx: "Context") -> Path | None:
    asset = _asset_for_arch(ctx.facts.arch)
    url = f"https://github.com/{_REPO}/releases/download/{_PINNED_TAG}/{asset}"
    dest = Path(tempfile.gettempdir()) / asset
    if ctx.dry_run:
        return None
    try:
        urllib.request.urlretrieve(url, dest)  # noqa: S310
        dest.chmod(0o755)
        return dest
    except Exception as exc:  # network/asset issues are non-fatal
        ctx.log.warn("sni.download_failed", url=url, error=str(exc))
        return None


def _run_scan(ctx: "Context", binary: Path, cidr: str) -> str | None:
    # Keep the CSV under /var/log/shroud so the operator can inspect what the
    # scanner actually found (`cat /var/log/shroud/reality_scan.csv`).
    out = paths.log_dir() / "reality_scan.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    ctx.runner.run(
        [str(binary), "-addr", cidr, "-port", "443", "-thread", "10",
         "-timeout", "8", "-out", str(out)],
        mutating=False, timeout=180,
    )
    if not out.exists():
        ctx.log.warn("sni.scan_no_output", path=str(out))
        return None
    try:
        lines = out.read_text("utf-8").strip().splitlines()
    except OSError:
        return None
    # Scan EVERY cell of EVERY row; the first valid domain wins, regardless of
    # which column the current scanner build puts it in.
    for line in lines:
        for cell in line.split(","):
            cand = cell.strip().lstrip("*.")
            if is_valid_domain(cand):
                ctx.log.info("sni.candidate", domain=cand)
                return cand
    ctx.log.warn("sni.scan_no_domain", rows=len(lines))
    return None
