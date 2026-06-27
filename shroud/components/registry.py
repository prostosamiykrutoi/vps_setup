"""Map a profile protocol entry to its Component implementation."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Component
from .hysteria2 import Hysteria2Component
from .telemt import TelemtComponent
from .xray_3xui import Xray3xuiComponent

if TYPE_CHECKING:
    from ..context import Context

# Keyed by (type, transport) where transport disambiguates vless variants.
_BY_TYPE = {
    "hysteria2": Hysteria2Component,
    "telemt": TelemtComponent,
}


def component_for(ctx: "Context", proto: dict) -> Component | None:
    ptype = proto.get("type")
    if ptype == "vless":
        transport = proto.get("transport")
        if transport == "xhttp":
            return Xray3xuiComponent(ctx, proto)
        # ws+cdn variant is out of default scope; skip until implemented.
        ctx.log.warn("registry.unsupported_vless_transport", transport=transport)
        return None
    cls = _BY_TYPE.get(ptype)
    if cls is None:
        ctx.log.warn("registry.unknown_protocol", type=ptype)
        return None
    return cls(ctx, proto)


def build_enabled(ctx: "Context") -> list[Component]:
    comps: list[Component] = []
    for proto in ctx.enabled_protocols():
        comp = component_for(ctx, proto)
        if comp is not None:
            comps.append(comp)
    return comps
