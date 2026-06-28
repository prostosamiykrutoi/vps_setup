"""Phase 2 — Firewall (critical, nftables).

Applies a single declarative ruleset: default deny incoming / allow outgoing,
allow SSH + active inbound ports, drop ICMP echo-request (spec §1/§9), and keep
the panel port closed (loopback only, D1). Idempotent: the whole ruleset is
rendered and compared; ``nft -f`` replaces the table atomically.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..reconcile import Step

if TYPE_CHECKING:
    from ..context import Context

RULES_FILE = "/etc/nftables.shroud.conf"


def desired_ports(ctx: "Context") -> dict[str, set[int]]:
    """Return {'tcp': {...}, 'udp': {...}} of ports to open."""
    tcp: set[int] = set()
    udp: set[int] = set()

    # SSH: new port, plus 22 retained until operator confirms (no lock-out).
    tcp.add(ctx.ssh_port)
    if ctx.ssh_port != 22:
        tcp.add(22)

    panel = ctx.profile.panel if ctx.profile else {}
    sub_port = int(panel.get("sub_port", 2096))
    tcp.add(sub_port)
    tcp.add(80)  # nginx decoy / ACME http-01

    for proto in ctx.enabled_protocols():
        port = int(proto.get("port", 0))
        if not port:
            continue
        if proto.get("network_proto") == "udp":
            udp.add(port)
        else:
            tcp.add(port)
    # Panel port is intentionally excluded (loopback only).
    return {"tcp": tcp, "udp": udp}


def render_ruleset(ctx: "Context") -> str:
    ports = desired_ports(ctx)
    tcp = ", ".join(str(p) for p in sorted(ports["tcp"])) or "0"
    udp_block = ""
    if ports["udp"]:
        udp = ", ".join(str(p) for p in sorted(ports["udp"]))
        udp_block = f"        udp dport {{ {udp} }} accept\n"
    return f"""#!/usr/sbin/nft -f
# Managed by shroud. Do not edit; change the profile and run `shroud update`.
table inet shroud {{
    chain input {{
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept

        # Drop ICMP echo-request (hide from ping sweeps); keep needed types.
        ip protocol icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
        ip6 nexthdr ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert }} accept
        ip protocol icmp icmp type echo-request drop
        ip6 nexthdr ipv6-icmp icmpv6 type echo-request drop

        tcp dport {{ {tcp} }} accept
{udp_block}    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"""


class FirewallStep(Step):
    id = "firewall.nftables"
    critical = True

    def inputs(self):
        return desired_ports(self.ctx)

    def _root(self) -> Path:
        import os
        return Path(os.environ.get("SHROUD_ROOT", "/"))

    def _path(self) -> Path:
        return self._root() / RULES_FILE.lstrip("/")

    def _main_conf(self) -> Path:
        return self._root() / "etc/nftables.conf"

    _INCLUDE = f'include "{RULES_FILE}"'

    def _persisted(self) -> bool:
        conf = self._main_conf()
        return conf.exists() and self._INCLUDE in conf.read_text("utf-8")

    def check(self) -> bool:
        p = self._path()
        if not (p.exists() and p.read_text("utf-8") == render_ruleset(self.ctx)):
            return False
        if not self._persisted():            # must survive reboot
            return False
        res = self.ctx.runner.run(["nft", "list", "table", "inet", "shroud"],
                                  mutating=False)
        return res.ok or self.ctx.dry_run

    def apply(self) -> None:
        ctx = self.ctx
        if not ctx.runner.have("nft"):
            ctx.runner.run(["apt-get", "install", "-y", "-qq", "nftables"],
                           timeout=300)
        p = self._path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render_ruleset(ctx), "utf-8")
        # Replace just our table atomically, then load the file.
        ctx.runner.run(["nft", "delete", "table", "inet", "shroud"])  # ok if absent
        ctx.runner.run(["nft", "-f", str(p)], check=False)
        # Persist: nftables.service loads /etc/nftables.conf on boot, so make it
        # include our ruleset (otherwise the firewall is gone after a reboot).
        conf = self._main_conf()
        if not self._persisted():
            conf.parent.mkdir(parents=True, exist_ok=True)
            existing = conf.read_text("utf-8") if conf.exists() else "#!/usr/sbin/nft -f\n"
            if not existing.endswith("\n"):
                existing += "\n"
            conf.write_text(existing + self._INCLUDE + "\n", "utf-8")
        ctx.runner.run(["systemctl", "enable", "nftables"])

    def verify(self) -> bool:
        if self.ctx.dry_run:
            return True
        res = self.ctx.runner.run(["nft", "list", "table", "inet", "shroud"],
                                  mutating=False)
        return res.ok


def steps(ctx: "Context") -> list[Step]:
    return [FirewallStep(ctx)]
