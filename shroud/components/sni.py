"""Reality donor-SNI selection via XTLS/RealiTLScanner (verified v0.2.3).

Strategy (spec §9.1): scan the server's OWN subnet/ASN for a reachable TLS-1.3
donor in the same CIDR (co-location => no instant giveaway). Fall back to a
same-ASN/last-resort donor from the profile — never ``www.microsoft.com``.

RealiTLScanner CLI (verified): ``-addr`` accepts a CIDR, ``-port`` (def 443),
``-thread``, ``-out`` CSV with columns IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE.
Assets: ``RealiTLScanner-linux-amd64`` / ``-linux-arm64``.
"""
from __future__ import annotations

import ipaddress
import json
import tempfile
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context

_REPO = "XTLS/RealiTLScanner"
_PINNED_TAG = "v0.2.3"


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
    """Return a donor SNI: same-ASN scan result, else profile fallback."""
    proto = ctx.profile.protocol("vless-reality-xhttp") or {}
    fallbacks = [d for d in proto.get("sni_fallback", []) if "microsoft.com" not in d]
    fallback = fallbacks[0] if fallbacks else "dl.google.com"

    if proto.get("sni_strategy") != "same-asn-scan":
        return proto.get("static_sni", fallback)

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
    if donor:
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
    out = Path(tempfile.gettempdir()) / "shroud_donors.csv"
    res = ctx.runner.run(
        [str(binary), "-addr", cidr, "-port", "443", "-thread", "10",
         "-timeout", "8", "-out", str(out)],
        mutating=False, timeout=180,
    )
    if not out.exists():
        return None
    try:
        lines = out.read_text("utf-8").strip().splitlines()
    except OSError:
        return None
    # CSV: IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE. Pick first apex-ish domain.
    for line in lines[1:]:
        cols = [c.strip() for c in line.split(",")]
        if len(cols) >= 3 and cols[2] and "." in cols[2]:
            cert_domain = cols[2].lstrip("*.")
            if "microsoft.com" not in cert_domain:
                return cert_domain
    return None
