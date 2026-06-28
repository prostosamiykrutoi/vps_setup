"""Structured JSON logging with mandatory secret redaction.

Every secret value that the orchestrator generates or loads MUST be registered
with :func:`register_secret` so that it is masked anywhere it appears in a log
record — including inside rendered config snippets or subprocess output.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

# Substrings that, if they appear verbatim in a log payload, are masked.
_SECRETS: set[str] = set()
# Field-name fragments whose *values* are always masked regardless of content.
_SENSITIVE_KEYS = ("password", "secret", "privatekey", "private_key", "token",
                   "uuid", "auth", "cred", "psk", "pbk_priv")

_REDACTED = "***REDACTED***"


def register_secret(value: str | None) -> None:
    if value and len(value) >= 4:
        _SECRETS.add(value)


def _redact_str(s: str) -> str:
    for secret in _SECRETS:
        if secret in s:
            s = s.replace(secret, _REDACTED)
    return s


def _redact(obj: Any, key_hint: str = "") -> Any:
    if isinstance(obj, dict):
        return {k: _redact(v, key_hint=str(k).lower()) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_redact(v, key_hint=key_hint) for v in obj]
    if isinstance(obj, str):
        if any(frag in key_hint for frag in _SENSITIVE_KEYS):
            return _REDACTED
        return _redact_str(obj)
    return obj


class Logger:
    """Writes JSON-line records to stderr (human) and a file (audit)."""

    def __init__(self, log_path: Path | None = None, verbose: bool = False):
        self.verbose = verbose
        self.log_path = log_path
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # 0600 — logs may reference non-secret but sensitive operational data.
            self._fh = open(log_path, "a", encoding="utf-8")
            try:
                Path(log_path).chmod(0o600)
            except OSError:
                pass
        else:
            self._fh = None

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "event": event,
            **fields,
        }
        record = _redact(record)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if self._fh is not None:
            self._fh.write(line + "\n")
            self._fh.flush()
        if level != "debug" or self.verbose:
            stream = sys.stderr
            colour = {"error": "31", "warn": "33", "info": "36",
                      "debug": "90"}.get(level, "0")
            stream.write(f"\033[{colour}m[{level}]\033[0m {event} "
                         f"{json.dumps({k: v for k, v in record.items() if k not in ('ts', 'level', 'event')}, ensure_ascii=False)}\n")
            # Flush so diagnostics appear in real time (and aren't lost/reordered
            # in a non-TTY capture like CI on a fast run).
            stream.flush()

    def debug(self, event: str, **f: Any) -> None: self._emit("debug", event, **f)
    def info(self, event: str, **f: Any) -> None: self._emit("info", event, **f)
    def warn(self, event: str, **f: Any) -> None: self._emit("warn", event, **f)
    def error(self, event: str, **f: Any) -> None: self._emit("error", event, **f)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
