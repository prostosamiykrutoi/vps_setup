"""Shared fixtures: a sandboxed Context that writes under a tmp SHROUD_ROOT and
never touches the real system (the runner is forced into dry-run unless a test
opts out)."""
from __future__ import annotations

import os

import pytest

from shroud import profile as profile_mod
from shroud.context import Context
from shroud.log import Logger
from shroud.proc import Runner
from shroud.state import State


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("SHROUD_ROOT", str(root))
    # Reset path module memoisation is unnecessary (functions read env live).
    return root


@pytest.fixture()
def ctx(sandbox, tmp_path):
    log = Logger(tmp_path / "shroud.log", verbose=False)
    runner = Runner(log, dry_run=True)
    c = Context(
        role="standalone",
        mode="quick",
        lang="en",
        dry_run=True,
        profile=profile_mod.load(None),
        state=State(),
        log=log,
        runner=runner,
    )
    c.facts.public_ip4 = "203.0.113.7"
    c.facts.arch = "amd64"
    c.facts.os_id = "ubuntu"
    c.facts.os_version = "24.04"
    return c
