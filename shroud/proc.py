"""Subprocess wrapper used by every component/step.

Why a wrapper: it gives us (1) consistent logging with secret redaction,
(2) a single ``dry_run`` switch that turns mutating commands into no-ops while
still letting read-only probes execute, and (3) typed results instead of
scattered ``subprocess`` calls.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .log import Logger


@dataclass
class Result:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class Runner:
    def __init__(self, log: Logger, dry_run: bool = False):
        self.log = log
        self.dry_run = dry_run

    def have(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = False,
        mutating: bool = True,
        input_text: str | None = None,
        timeout: int = 120,
        env_extra: dict[str, str] | None = None,
    ) -> Result:
        """Run ``argv``.

        ``mutating=True`` commands are skipped (logged) under ``dry_run``;
        read-only probes should pass ``mutating=False`` so plans can be built.
        """
        if self.dry_run and mutating:
            self.log.info("dry_run.skip", cmd=list(argv))
            return Result(0, "", "")

        self.log.debug("exec", cmd=list(argv))
        import os
        env = None
        if env_extra:
            env = {**os.environ, **env_extra}
        try:
            proc = subprocess.run(
                list(argv),
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except FileNotFoundError as exc:
            self.log.error("exec.notfound", cmd=list(argv), error=str(exc))
            res = Result(127, "", str(exc))
            if check:
                raise CommandError(argv, res) from exc
            return res
        except subprocess.TimeoutExpired as exc:
            self.log.error("exec.timeout", cmd=list(argv), timeout=timeout)
            res = Result(124, exc.stdout or "", exc.stderr or "")
            if check:
                raise CommandError(argv, res) from exc
            return res

        res = Result(proc.returncode, proc.stdout or "", proc.stderr or "")
        if not res.ok:
            self.log.debug("exec.nonzero", cmd=list(argv), code=res.code,
                           stderr=res.stderr[-500:])
        if check and not res.ok:
            raise CommandError(argv, res)
        return res


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], result: Result):
        self.argv = list(argv)
        self.result = result
        super().__init__(f"command failed ({result.code}): {' '.join(argv)}\n"
                         f"{result.stderr[-800:]}")
