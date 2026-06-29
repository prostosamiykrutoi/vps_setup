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

from .. import paths, reality, secrets_util
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

        # Subscription id (per-client; ties the client to its /sub/<id> link).
        sub_id = st.get_ref("reality_sub_id")
        if not sub_id:
            sub_id = secrets_util.gen_hex(8)
            st.set_ref("reality_sub_id", sub_id)
        self._sub_id = sub_id

        # Donor SNI (same-ASN scan, else fallback). Re-validate any cached value
        # so a previously-stored bad SNI (e.g. an old "TLS 1.3") gets replaced.
        cached = st.get_ref("reality_sni")
        if cached and sni.is_valid_domain(cached):
            self._sni = cached
        else:
            self._sni = sni.select_donor(ctx)
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
        db = self._db_path()

        # 1. Wait for the panel's FIRST boot to finish (it creates + migrates the
        # SQLite DB and the default admin). Setting credentials before this races
        # the migration and the new password silently doesn't stick — which is
        # exactly why the panel rejected the password on the first real-VPS run.
        for _ in range(30):
            if db.exists():
                break
            time.sleep(1.5)
        self._wait_panel(panel_port, "")
        time.sleep(2)

        # 2. Set credentials AND create the inbound by writing 3x-ui's SQLite DB
        # directly (both done with the container stopped, then restart).
        # IMPORTANT (learned on a real VPS): this image has NO `x-ui setting`
        # flag command — credential change is only the interactive menu option
        # "7. Reset Username & Password". So `x-ui setting -username ...` was a
        # silent no-op and the panel kept its default `admin` user. We instead
        # bcrypt the password and write the users + inbounds tables directly,
        # the same deterministic path we already use for the inbound.
        self._provision_db()

    def _db_path(self):
        return paths.runtime_dir() / "3xui" / "db" / "x-ui.db"

    def _provision_db(self) -> None:
        ctx = self.ctx
        db = self._db_path()
        for _ in range(20):                       # wait for the panel to create it
            if db.exists():
                break
            time.sleep(1.5)
        if not db.exists():
            ctx.log.warn("3xui.db_missing", path=str(db))
            return
        already = self._inbound_in_db(db)
        # Stop the panel to write its DB safely (creds + inbound), then start so
        # the panel picks up the new login and xray regenerates its config.
        ctx.runner.run(["docker", "stop", "shroud-3xui"], timeout=60)
        creds_ok = self._set_panel_creds_db(db)
        inserted = False if already else self._insert_inbound_db(db)
        ctx.runner.run(["docker", "start", "shroud-3xui"], timeout=60)
        time.sleep(5)
        ctx.log.info("3xui.provisioned", creds_set=creds_ok,
                     inbound_inserted=inserted, already=already)

    def _set_panel_creds_db(self, db) -> bool:
        """Set the panel admin username/password by writing the users table.

        3x-ui stores the password as bcrypt ($2a$). We generate a matching
        $2a$ hash and UPDATE the (single) admin row — the only reliable
        non-interactive path in this image.
        """
        import sqlite3
        try:
            import bcrypt
        except Exception:
            self.ctx.log.warn("3xui.bcrypt_missing",
                              hint="pip install bcrypt; panel keeps default admin")
            return False
        try:
            hashed = bcrypt.hashpw(
                self._panel_pass.encode(),
                bcrypt.gensalt(rounds=10, prefix=b"2a")).decode()
            con = sqlite3.connect(str(db))
            try:
                cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
                if not cols:
                    return False
                count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                if count == 0:
                    con.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (self._panel_user, hashed))
                else:
                    con.execute(
                        "UPDATE users SET username=?, password=? "
                        "WHERE id=(SELECT MIN(id) FROM users)",
                        (self._panel_user, hashed))
                con.commit()
                self.ctx.log.info("3xui.creds_set", user=self._panel_user)
                return True
            finally:
                con.close()
        except Exception as exc:
            self.ctx.log.warn("3xui.creds_error", error=str(exc))
            return False

    def _inbound_in_db(self, db) -> bool:
        import sqlite3
        try:
            con = sqlite3.connect(str(db))
            try:
                cur = con.execute(
                    "SELECT COUNT(*) FROM inbounds WHERE remark=?",
                    ("shroud-vless-reality",))
                return cur.fetchone()[0] > 0
            finally:
                con.close()
        except Exception:
            return False

    def _insert_inbound_db(self, db) -> bool:
        import sqlite3
        inbound = self._build_inbound()
        row = {
            "user_id": 1, "up": 0, "down": 0, "total": 0,
            "remark": inbound["remark"], "enable": 1, "expiry_time": 0,
            "listen": "", "port": inbound["port"], "protocol": "vless",
            "settings": inbound["settings"],
            "stream_settings": inbound["streamSettings"],
            "tag": f"inbound-{inbound['port']}",
            "sniffing": inbound["sniffing"],
            "allocate": json.dumps(
                {"strategy": "always", "refresh": 5, "concurrency": 3}),
        }
        try:
            con = sqlite3.connect(str(db))
            try:
                cols = {r[1] for r in con.execute("PRAGMA table_info(inbounds)")}
                if not cols:
                    self.ctx.log.warn("3xui.db_no_table")
                    return False
                use = {k: v for k, v in row.items() if k in cols}
                fields = ", ".join(use)
                placeholders = ", ".join("?" * len(use))
                con.execute(
                    f"INSERT INTO inbounds ({fields}) VALUES ({placeholders})",
                    list(use.values()))
                con.commit()
                return True
            finally:
                con.close()
        except Exception as exc:
            self.ctx.log.warn("3xui.db_insert_error", error=str(exc))
            return False

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
                "email": f"shroud-{self._uuid[:8]}",   # 3x-ui requires unique email
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": "",
                "subId": self._sub_id,           # enables the subscription link
                "reset": 0,
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
