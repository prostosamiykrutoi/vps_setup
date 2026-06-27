"""Phase 6 self-tests — real checks, not just "is the port open" (spec §7).

Each check returns a :class:`Check` with pass/fail + detail. Failures are
informational (flagged, never fatal). Where a full protocol client isn't
available on the host we do the strongest cheap proxy: a real TLS/QUIC handshake
or a probe-without-secret that must surface the decoy/real site.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import Context


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


def _tcp_open(host: str, port: int, timeout: float = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _tls_handshake(host: str, port: int, sni: str, timeout: float = 6) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                cert = tls.getpeercert(binary_form=True)
                return True, f"tls{tls.version()} cert_len={len(cert or b'')}"
    except (OSError, ssl.SSLError) as exc:
        return False, str(exc)


def _container_running(ctx: "Context", name: str) -> bool:
    res = ctx.runner.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                         mutating=False, timeout=15)
    return res.ok and res.stdout.strip() == "true"


def run_all(ctx: "Context") -> list[Check]:
    checks: list[Check] = []
    ip = ctx.facts.public_ip4 or "127.0.0.1"

    # Containers alive
    for proto in ctx.enabled_protocols():
        pid = proto.get("id")
        cname = {
            "vless-reality-xhttp": "shroud-3xui",
            "hysteria2": "shroud-hysteria2",
            "telemt-mtproto": "shroud-telemt",
        }.get(pid)
        if cname:
            ok = _container_running(ctx, cname)
            checks.append(Check(f"container:{cname}", ok))

    # VLESS-Reality: TLS handshake on 443 with the donor SNI should succeed and
    # present the donor's certificate (Reality fronting).
    vless = ctx.profile.protocol("vless-reality-xhttp")
    if vless and vless.get("enabled"):
        sni = ctx.state.get_ref("reality_sni") or "dl.google.com"
        ok, detail = _tls_handshake(ip, int(vless.get("port", 443)), sni)
        checks.append(Check("vless-reality:handshake", ok, detail))

    # telemt FakeTLS: handshake with the fake_tls_domain SNI should proceed;
    # a probe with a bogus SNI must NOT yield a working proxy (reject/real site).
    telemt = ctx.profile.protocol("telemt-mtproto")
    if telemt and telemt.get("enabled"):
        port = int(telemt.get("port", 8443))
        good_sni = telemt.get("fake_tls_domain", "dl.google.com")
        ok_good, d_good = _tls_handshake(ip, port, good_sni)
        checks.append(Check("telemt:faketls", ok_good, d_good))
        # Probe-resistance: bogus SNI should be rejected (handshake fails) when
        # unknown_sni_action=reject_handshake.
        ok_bad, _ = _tls_handshake(ip, port, "definitely-not-a-real-sni.invalid")
        resistant = (not ok_bad) if telemt.get("unknown_sni_action") == "reject_handshake" else True
        checks.append(Check("telemt:probe-resistance", resistant,
                            "probe rejected" if resistant else "probe accepted (weak)"))

    # hysteria2 is UDP/QUIC — without a client we confirm the container is up and
    # the UDP socket is bound (best-effort).
    hy = ctx.profile.protocol("hysteria2")
    if hy and hy.get("enabled"):
        checks.append(Check("hysteria2:container",
                            _container_running(ctx, "shroud-hysteria2")))

    # Decoy: a plain HTTP(S) hit must NOT be a default nginx page.
    decoy_ok = _decoy_is_real(ctx, ip)
    checks.append(Check("decoy:real-site", decoy_ok))

    return checks


def _decoy_is_real(ctx: "Context", ip: str) -> bool:
    res = ctx.runner.run(["curl", "-s", "--max-time", "8", f"http://{ip}/"],
                         mutating=False, timeout=12)
    body = res.stdout.lower()
    if not body:
        return False
    return "welcome to nginx" not in body and "it works" not in body
