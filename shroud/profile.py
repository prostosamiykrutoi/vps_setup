"""Profile = the volatile layer (versions + protocol params), loaded from YAML
and validated against ``profiles/schema.json``.

Delivery (D5): the embedded ``profiles/default.yml`` works offline; ``--profile
<path|url>`` or ``shroud update`` may pull a newer pinned profile. Either way it
is *always* validated before use.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import yaml

_PKG_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = _PKG_ROOT / "profiles" / "default.yml"
SCHEMA_FILE = _PKG_ROOT / "profiles" / "schema.json"


class ProfileError(ValueError):
    pass


class Profile:
    def __init__(self, data: dict):
        self.data = data

    # ----- typed accessors ---------------------------------------------------
    @property
    def version(self) -> str:
        return str(self.data.get("version", "unknown"))

    @property
    def images(self) -> dict[str, dict]:
        return self.data.get("images", {})

    @property
    def protocols(self) -> list[dict]:
        return self.data.get("protocols", [])

    def enabled_protocols(self) -> list[dict]:
        return [p for p in self.protocols if p.get("enabled")]

    def protocol(self, proto_id: str) -> dict | None:
        for p in self.protocols:
            if p.get("id") == proto_id:
                return p
        return None

    @property
    def decoy(self) -> dict:
        return self.data.get("decoy", {})

    @property
    def panel(self) -> dict:
        return self.data.get("panel", {"bind": "127.0.0.1", "access": "ssh-forward"})

    def image_ref(self, key: str) -> str:
        """Return ``repo:tag@digest`` (or ``repo:tag``) for an image key."""
        img = self.images.get(key)
        if not img:
            raise ProfileError(f"profile has no image entry '{key}'")
        repo, tag = img.get("repo"), img.get("tag")
        if not repo or not tag:
            raise ProfileError(f"image '{key}' missing repo/tag")
        digest = img.get("digest")
        ref = f"{repo}:{tag}"
        if digest:
            ref += f"@{digest}"
        return ref


def _load_schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text("utf-8"))


def validate(data: dict) -> None:
    """Validate against schema.json. Uses jsonschema if present, else a minimal
    structural fallback so the tool still refuses obviously broken profiles."""
    schema = _load_schema()
    try:
        import jsonschema  # type: ignore
    except ImportError:
        _minimal_validate(data)
        return
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ProfileError(f"profile failed schema validation: {exc.message}") from exc


def _minimal_validate(data: dict) -> None:
    for req in ("version", "images", "protocols"):
        if req not in data:
            raise ProfileError(f"profile missing required top-level key '{req}'")
    if not isinstance(data["protocols"], list) or not data["protocols"]:
        raise ProfileError("profile.protocols must be a non-empty list")
    for p in data["protocols"]:
        for req in ("id", "enabled", "type"):
            if req not in p:
                raise ProfileError(f"protocol entry missing '{req}': {p!r}")


def load(source: str | Path | None = None) -> Profile:
    """Load + validate a profile from a path, URL, or the embedded default."""
    if source is None:
        raw = DEFAULT_PROFILE.read_text("utf-8")
    elif str(source).startswith(("http://", "https://")):
        with urllib.request.urlopen(str(source), timeout=20) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
    else:
        raw = Path(source).read_text("utf-8")

    data: Any = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ProfileError("profile root must be a mapping")
    validate(data)
    return Profile(data)
