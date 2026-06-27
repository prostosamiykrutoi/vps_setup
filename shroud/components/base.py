"""Base class describing a stack component.

A component is declarative: it tells the stack phase what secrets it needs, what
config files to write, what compose service to run, which firewall ports to open,
and what client links to emit. The stack phase does the actual compose up.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context


class Component:
    type: str = "base"

    def __init__(self, ctx: "Context", proto: dict):
        self.ctx = ctx
        self.proto = proto

    @property
    def id(self) -> str:
        return self.proto.get("id", self.type)

    @property
    def port(self) -> int:
        return int(self.proto.get("port", 0))

    @property
    def net_proto(self) -> str:
        return self.proto.get("network_proto", "tcp")

    # ----- lifecycle hooks (override as needed) ------------------------------
    def prepare_secrets(self) -> None:
        """Generate or load secrets; store refs in state, raw in ctx.credentials."""

    def render(self, runtime_dir: Path) -> None:
        """Write config file(s) under runtime_dir."""

    def compose_service(self) -> tuple[str, dict] | None:
        """Return (service_name, service_dict) for docker-compose, or None."""
        return None

    def firewall_ports(self) -> list[tuple[int, str]]:
        if self.port:
            return [(self.port, self.net_proto)]
        return []

    def links(self) -> list[tuple[str, str]]:
        """Return [(label, connection_uri), ...] for the summary/subscription."""
        return []

    # ----- helpers -----------------------------------------------------------
    def _image(self, key: str) -> str:
        return self.ctx.profile.image_ref(key)
