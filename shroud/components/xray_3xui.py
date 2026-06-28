"""3x-ui panel + xray (VLESS + Reality + XHTTP). Versions/endpoints verified
upstream (3x-ui v3.4.1): panel on loopback (D1), inbound via /panel/api, login
cookie ``3x-ui``. Clients in v3.x live under /panel/api/clients.

The panel UI/API listens only on 127.0.0.1 (reached via SSH local-forward). The
VLESS inbound itself listens on the public 443.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import TYPE_CHECKING

from .. import reality, secrets_util
from ..log import register_secret
from .base import Component
from . import sni

if TYPE_CHECKING:
    from ..context import Context

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


class Xray3xuiComponent(Component):
    type = "vless"

    def prepare_secrets(self) -> None:
        ctx = self.ctx
        st = ctx.state

        user = st.get_ref("panel_user") or secrets_util.gen_username()
        pwd = st.get_ref("panel_pass_marker")  # marker only; raw never in state
        if not pwd:
            raw_pwd = secrets_util.gen_password()
            st.set_ref("panel_pass_marker", "set")
            ctx.credentials["panel_pass"] = raw_pwd
            self._panel_pass = raw_pwd
        else:
            # On a reconcile we re-roll the password only if we don't hold it.
            self._panel_pass = ctx.credentials.get("panel_pass") or secrets_util.gen_password()
            ctx.credentials["panel_pass"] = self._panel_pass
        st.set_ref("panel_user", user)
        self._panel_user = user
        register_secret(self._panel_pass)
        ctx.credentials["panel_user"] = user

        # Reality keypair (persist public; private only in xray config + creds).
        pub = st.get_ref("reality_pbk")
        if not pub:
            priv, pub = reality.generate_keypair(ctx)
            st.set_ref("reality_pbk", pub)
            ctx.credentials["reality_private_key"] = priv
            self._reality_priv = priv
        else:
            self._reality_priv = ctx.credentials.get("reality_private_key", "")
        self._reality_pub = pub

        uuid = st.get_ref("vless_uuid")
        if not uuid:
            uuid = secrets_util.gen_uuid()
            st.set_ref("vless_uuid", uuid)
        self._uuid = uuid

        sid = st.get_ref("reality_short_id")
        if not sid:
            sid = secrets_util.gen_short_id()
            st.set_ref("reality_short_id", sid)
        self._short_id = sid

        # Donor SNI (same-ASN scan, else fallback). Cache in state.
        self._sni = st.get_ref("reality_sni") or sni.select_donor(ctx)
        st.set_ref("reality_sni", self._sni)

    # ----- config / compose --------------------------------------------------
    def render(self, runtime_dir: Path) -> None:
        (runtime_dir / "3xui" / "db").mkdir(parents=True, exist_ok=True)
        (runtime_dir / "3xui" / "cert").mkdir(parents=True, exist_ok=True)

    def compose_service(self) -> tuple[str, dict]:
        panel = self.ctx.profile.panel
        panel_port = int(panel.get("port", 2053))
        sub_port = int(panel.get("sub_port", 2096))
        svc = {
            "image": self._image("xray_3xui"),
            "container_name": "shroud-3xui",
            "restart": "unless-stopped",
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "volumes": [
                "./3xui/db:/etc/x-ui",
                "./certs:/root/cert:ro",
            ],
            "ports": [
                # Panel/API: loopback ONLY (D1).
                f"127.0.0.1:{panel_port}:{panel_port}",
                # VLESS-Reality inbound: public.
                f"{self.port}:{self.port}",
                # Subscription server (client-reachable; serves share links only).
                f"{sub_port}:{sub_port}",
            ],
            "environment": ["XRAY_VMESS_AEAD_FORCED=false"],
        }
        return "3xui", svc

    def firewall_ports(self) -> list[tuple[int, str]]:
        sub_port = int(self.ctx.profile.panel.get("sub_port", 2096))
        # Panel port intentionally NOT opened (loopback only).
        return [(self.port, "tcp"), (sub_port, "tcp")]

    # ----- post-up provisioning (live; skipped under dry-run) ----------------
    def provision(self) -> None:
        """Configure panel creds/bind and create the inbound via API.

        Called by the stack phase AFTER `compose up`. Idempotent: skips inbound
        creation if one with our remark already exists.
        """
        ctx = self.ctx
        if ctx.dry_run:
            return
        panel = ctx.profile.panel
        panel_port = int(panel.get("port", 2053))

        # 1. Set panel credentials via the in-container CLI.
        # NOTE: do NOT set -listenIP 127.0.0.1 here. Inside the container that
        # would bind the panel to the container's loopback, which Docker's port
        # publish (DNAT to the container's eth0) can't reach. Loopback-only
        # exposure (D1) is enforced at the HOST level by publishing the port as
        # 127.0.0.1:2053:2053 in compose; the panel binds 0.0.0.0 in-container.
        ctx.runner.run(
            ["docker", "exec", "shroud-3xui", "x-ui", "setting",
             "-username", self._panel_user, "-password", self._panel_pass,
             "-port", str(panel_port)],
            timeout=60,
        )
        # Best-effort: pin the web base path to root so the API lives at /login.
        # Fresh 3x-ui installs generate a RANDOM webBasePath; hitting /login then
        # returns 403. If the flag is unsupported this call just fails harmlessly
        # and we fall back to discovering the real base path below.
        ctx.runner.run(
            ["docker", "exec", "shroud-3xui", "x-ui", "setting",
             "-webBasePath", "/"], timeout=60)
        ctx.runner.run(["docker", "restart", "shroud-3xui"], timeout=60)
        time.sleep(5)  # let the panel re-read settings and bind before we probe

        # 2. Discover the ACTUAL port + base path the panel ended up with, rather
        # than assuming. This is what fixes the 403-on-/login failure.
        port, base = self._read_panel_settings(panel_port)
        self._panel_base_path = base
        ctx.log.info("3xui.discovered", port=port, base_path=base or "/")
        self._wait_panel(port, base)

        api = _PanelAPI(f"http://127.0.0.1:{port}{base}", ctx)
        if not api.login(self._panel_user, self._panel_pass):
            ctx.log.warn("3xui.login_failed", base_path=base or "/")
            return
        if api.inbound_exists("shroud-vless-reality"):
            ctx.log.info("3xui.inbound_exists")
            return
        ok = api.add_inbound(self._build_inbound())
        ctx.log.info("3xui.inbound_added", ok=ok)
        if ok:
            time.sleep(3)  # let xray restart and start listening on :443

    def _read_panel_settings(self, default_port: int) -> tuple[int, str]:
        """Parse `x-ui setting -show` for the real port + web base path.

        Returns (port, base_suffix) where base_suffix is '' for root or '/xyz'.
        """
        res = self.ctx.runner.run(
            ["docker", "exec", "shroud-3xui", "x-ui", "setting", "-show"],
            mutating=False, timeout=30)
        out = res.stdout if res.ok else ""
        port = default_port
        m = re.search(r"(?im)^\s*port\s*[:=]\s*(\d+)", out)
        if m:
            port = int(m.group(1))
        base = ""
        b = re.search(r"(?im)base\s*path\s*[:=]\s*(\S*)", out)
        if b:
            raw = b.group(1).strip()
            if raw and raw != "/":
                base = "/" + raw.strip("/")
        return port, base

    def _wait_panel(self, port: int, base: str = "", attempts: int = 25) -> None:
        # Server is "up" as soon as it answers with ANY HTTP status (a base-path
        # panel returns 404 on '/', which still means it's listening).
        url = f"http://127.0.0.1:{port}{base}/"
        for _ in range(attempts):
            res = self.ctx.runner.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
                mutating=False, timeout=10)
            if res.stdout.strip() not in ("", "000"):
                return
            time.sleep(1.5)

    def _build_inbound(self) -> dict:
        settings = {
            "clients": [{
                "id": self._uuid,
                "flow": "",                      # MUST be empty for xhttp+reality
                "email": "shroud",
                "enable": True,
            }],
            "decryption": "none",
            "fallbacks": [],
        }
        stream = {
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": {
                "path": self.proto.get("xhttp_path", "/"),
                "mode": self.proto.get("xhttp_mode", "auto"),
            },
            "realitySettings": {
                "show": False,
                "dest": f"{self._sni}:443",
                "xver": 0,
                "serverNames": [self._sni],
                "privateKey": self._reality_priv,
                "shortIds": [self._short_id],
                "fingerprint": self.proto.get("fingerprint", "chrome"),
            },
        }
        return {
            "remark": "shroud-vless-reality",
            "enable": True,
            "protocol": "vless",
            "listen": "",
            "port": self.port,
            "expiryTime": 0,
            "settings": json.dumps(settings),
            "streamSettings": json.dumps(stream),
            "sniffing": json.dumps({"enabled": False, "destOverride": []}),
        }

    def links(self) -> list[tuple[str, str]]:
        ip = self.ctx.facts.public_ip4 or "SERVER_IP"
        path = self.proto.get("xhttp_path", "/")
        fp = self.proto.get("fingerprint", "chrome")
        uri = (f"vless://{self._uuid}@{ip}:{self.port}"
               f"?encryption=none&security=reality&type=xhttp"
               f"&path={path}&host=&mode={self.proto.get('xhttp_mode', 'auto')}"
               f"&sni={self._sni}&fp={fp}&pbk={self._reality_pub}"
               f"&sid={self._short_id}#shroud-reality")
        return [("VLESS-Reality-XHTTP", uri)]


class _PanelAPI:
    """Minimal 3x-ui API client (urllib + cookiejar; cookie name '3x-ui')."""

    def __init__(self, base: str, ctx: "Context"):
        self.base = base.rstrip("/")
        self.ctx = ctx
        self.cj = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))

    def _common_headers(self) -> dict:
        # Many gin-based panels enforce a CSRF/Referer check on POSTs; send a
        # matching Origin/Referer plus a browser UA so the request looks like it
        # came from the panel's own login page.
        origin = self.base or "http://127.0.0.1"
        return {
            "User-Agent": _UA,
            "Origin": origin,
            "Referer": origin + "/",
            "X-Requested-With": "XMLHttpRequest",
        }

    def _seed_cookies(self) -> None:
        """GET the panel root once to obtain the session/CSRF cookie."""
        req = urllib.request.Request(self.base + "/", method="GET",
                                     headers=self._common_headers())
        try:
            with self.opener.open(req, timeout=15):
                pass
        except urllib.error.HTTPError:
            pass  # even a 4xx sets cookies
        except (urllib.error.URLError, OSError):
            pass

    def _post(self, path: str, data: dict, as_json: bool = False) -> dict | None:
        url = self.base + path
        headers = self._common_headers()
        if as_json:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        else:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=20) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            snippet = ""
            try:
                snippet = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            self.ctx.log.warn("3xui.api_http", path=path, code=exc.code,
                              body=snippet)
            return None
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            self.ctx.log.warn("3xui.api_error", path=path, error=str(exc))
            return None

    def login(self, user: str, pwd: str) -> bool:
        self._seed_cookies()
        r = self._post("/login", {"username": user, "password": pwd})
        if r is None:
            return False
        if not r.get("success"):
            self.ctx.log.warn("3xui.login_rejected", msg=str(r.get("msg"))[:120])
            return False
        return True

    def inbound_exists(self, remark: str) -> bool:
        url = self.base + "/panel/api/inbounds/list"
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
        try:
            with self.opener.open(req, timeout=20) as resp:
                data = json.loads(resp.read().decode() or "{}")
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return False
        for ib in (data.get("obj") or []):
            if ib.get("remark") == remark:
                return True
        return False

    def add_inbound(self, inbound: dict) -> bool:
        r = self._post("/panel/api/inbounds/add", inbound)
        return bool(r and r.get("success"))
