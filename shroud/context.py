"""Context: the single object threaded through phases, steps and components.

Holds resolved options (role/mode/lang/ports), the loaded profile, mutable
state, the logger, the i18n translator, the process runner, and discovered
system facts (filled by preflight). Keeping these together avoids global state
and makes the whole pipeline trivially testable with a fake context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import paths, state as state_mod
from .i18n import Translator
from .log import Logger
from .proc import Runner
from .profile import Profile


@dataclass
class SystemFacts:
    os_id: str = ""
    os_version: str = ""
    arch: str = ""            # amd64 | arm64
    public_ip4: str | None = None
    public_ip6: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    throttled_asn: bool = False


@dataclass
class Context:
    role: str = "standalone"
    mode: str = "quick"            # quick | interactive
    lang: str = "en"
    dry_run: bool = False
    assume_yes: bool = False
    verbose: bool = False
    strict: bool = False

    ssh_port: int = 22
    panel_port: int = 2053
    exit_bundle: str | None = None   # for role=entry

    profile: Profile = None          # type: ignore[assignment]
    state: state_mod.State = field(default_factory=state_mod.State)
    facts: SystemFacts = field(default_factory=SystemFacts)

    log: Logger = None               # type: ignore[assignment]
    runner: Runner = None            # type: ignore[assignment]
    _t: Translator = None            # type: ignore[assignment]

    # Collected outputs for the final summary (non-secret references + links).
    summary: dict[str, Any] = field(default_factory=dict)
    # Secret material destined ONLY for /root/shroud-credentials.txt.
    credentials: dict[str, str] = field(default_factory=dict)
    # Built stack components (populated by the stack phase).
    components: list = field(default_factory=list)
    # Collected client links: list of (label, uri).
    links: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.log is None:
            self.log = Logger(paths.log_dir() / "shroud.log", verbose=self.verbose)
        if self.runner is None:
            self.runner = Runner(self.log, dry_run=self.dry_run)
        if self._t is None:
            self._t = Translator(self.lang)

    def t(self, key: str, *args: object) -> str:
        return self._t(key, *args)

    def prompt(self, label: str, default: str) -> str:
        """Interactive prompt honouring quick/--yes; returns default otherwise."""
        if self.mode != "interactive" or self.assume_yes:
            return default
        try:
            raw = input(self.t("prompt_default", label, default))
        except EOFError:
            return default
        return raw.strip() or default

    def enabled_protocols(self) -> list[dict]:
        return self.profile.enabled_protocols() if self.profile else []
