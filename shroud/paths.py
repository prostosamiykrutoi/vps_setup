"""Filesystem locations used across shroud.

Centralised so tests can monkeypatch a temporary root via the ``SHROUD_ROOT``
environment variable instead of writing to real system paths.
"""
from __future__ import annotations

import os
from pathlib import Path


def _root() -> Path:
    return Path(os.environ.get("SHROUD_ROOT", "/"))


def state_file() -> Path:
    return _root() / "var/lib/shroud/state.json"


def log_dir() -> Path:
    return _root() / "var/log/shroud"


def runtime_dir() -> Path:
    """Where rendered compose files and component configs are materialised."""
    return _root() / "opt/shroud/runtime"


def credentials_file() -> Path:
    return _root() / "root/shroud-credentials.txt"


def connect_info_file() -> Path:
    return _root() / "root/shroud-connect-info.json"


def backup_dir() -> Path:
    return _root() / "var/lib/shroud/backups"
