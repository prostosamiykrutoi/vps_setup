"""Persistent state: ``/var/lib/shroud/state.json`` (mode 0600).

State stores *references/identifiers* (e.g. panel username, Reality public key)
and per-step success + input hash — never raw secrets. Raw secrets live only in
the component config files and in ``/root/shroud-credentials.txt``.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from . import SCHEMA_VERSION, __version__
from . import paths


def hash_inputs(payload: Any) -> str:
    """Stable sha256 over a step's declared inputs, for drift detection."""
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class State:
    role: str = "standalone"
    profile_version: str | None = None
    applied_steps: dict[str, dict] = field(default_factory=dict)
    generated_refs: dict[str, str] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    tool_version: str = __version__
    updated_at: str | None = None

    # ----- step bookkeeping --------------------------------------------------
    def step_converged(self, step_id: str, input_hash: str) -> bool:
        rec = self.applied_steps.get(step_id)
        return bool(rec and rec.get("ok") and rec.get("input_hash") == input_hash)

    def record_step(self, step_id: str, ok: bool, input_hash: str) -> None:
        self.applied_steps[step_id] = {
            "ok": ok,
            "input_hash": input_hash,
            "ts": _now(),
        }

    def set_ref(self, key: str, value: str) -> None:
        self.generated_refs[key] = value

    def get_ref(self, key: str, default: str | None = None) -> str | None:
        return self.generated_refs.get(key, default)

    # ----- persistence -------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "profile_version": self.profile_version,
            "role": self.role,
            "applied_steps": self.applied_steps,
            "generated_refs": self.generated_refs,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "State":
        return cls(
            role=d.get("role", "standalone"),
            profile_version=d.get("profile_version"),
            applied_steps=d.get("applied_steps", {}),
            generated_refs=d.get("generated_refs", {}),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            tool_version=d.get("tool_version", __version__),
            updated_at=d.get("updated_at"),
        )


def load() -> State:
    p = paths.state_file()
    if not p.exists():
        return State()
    try:
        return State.from_dict(json.loads(p.read_text("utf-8")))
    except (json.JSONDecodeError, OSError):
        # Corrupt state must not brick the tool; start fresh but keep a backup.
        try:
            p.rename(p.with_suffix(".json.corrupt"))
        except OSError:
            pass
        return State()


def save(state: State) -> None:
    state.updated_at = _now()
    p = paths.state_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state.to_dict(), indent=2, ensure_ascii=False), "utf-8")
    tmp.chmod(0o600)
    tmp.replace(p)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
