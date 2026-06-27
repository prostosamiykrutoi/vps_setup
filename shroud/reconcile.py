"""Reconcile engine: the idempotency contract from the spec (§6).

A :class:`Step` declares ``check`` (is the desired state already reached?),
``apply`` (reach it), ``verify`` (confirm after apply) and optional
``rollback``. The engine runs, per step in order::

    if not check(): apply(); assert verify()

Critical-step failures abort safely (state already persisted). Non-critical
failures are logged and execution continues, yielding a partial result.
``dry_run`` runs every ``check`` only and accumulates a diff.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from . import state as state_mod

if TYPE_CHECKING:
    from .context import Context


class Outcome(str, Enum):
    CONVERGED = "converged"      # check() already true
    CHANGED = "changed"          # apply() ran and verify() passed
    FAILED = "failed"            # verify() failed (or apply raised)
    PLANNED = "planned"          # dry-run: would change
    SKIPPED = "skipped"          # not applicable for this role/profile


class Step:
    """Base class. Subclasses override check/apply/verify and set id/critical."""

    id: str = "unnamed"
    critical: bool = False

    def __init__(self, ctx: "Context"):
        self.ctx = ctx

    # The declared inputs that, when changed, mean the step must re-run.
    def inputs(self) -> Any:
        return {}

    def check(self) -> bool:
        raise NotImplementedError

    def apply(self) -> None:
        raise NotImplementedError

    def verify(self) -> bool:
        # Default: re-use check() as the post-apply confirmation.
        return self.check()

    def rollback(self) -> None:
        return None

    # Allows a step to opt out (e.g. cascade steps when role=standalone).
    def applicable(self) -> bool:
        return True


@dataclass
class StepResult:
    step_id: str
    outcome: Outcome
    critical: bool
    detail: str = ""


@dataclass
class ReconcileReport:
    results: list[StepResult] = field(default_factory=list)
    aborted: bool = False

    def add(self, r: StepResult) -> None:
        self.results.append(r)

    @property
    def changed(self) -> list[StepResult]:
        return [r for r in self.results if r.outcome in (Outcome.CHANGED, Outcome.PLANNED)]

    @property
    def failed(self) -> list[StepResult]:
        return [r for r in self.results if r.outcome == Outcome.FAILED]


class CriticalStepFailed(RuntimeError):
    def __init__(self, step_id: str):
        self.step_id = step_id
        super().__init__(step_id)


class Engine:
    def __init__(self, ctx: "Context"):
        self.ctx = ctx

    def run(self, steps: list[Step], report: ReconcileReport | None = None) -> ReconcileReport:
        report = report or ReconcileReport()
        ctx = self.ctx
        for step in steps:
            if not step.applicable():
                report.add(StepResult(step.id, Outcome.SKIPPED, step.critical))
                continue

            input_hash = state_mod.hash_inputs(step.inputs())

            # Fast-path: state says converged AND inputs unchanged AND check() agrees.
            try:
                already = step.check()
            except Exception as exc:  # a check must never brick the run
                ctx.log.error("step.check_error", step=step.id, error=str(exc))
                already = False

            if already:
                ctx.state.record_step(step.id, True, input_hash)
                report.add(StepResult(step.id, Outcome.CONVERGED, step.critical))
                ctx.log.info("step", msg=ctx.t("step.ok_already", step.id))
                continue

            if ctx.dry_run:
                report.add(StepResult(step.id, Outcome.PLANNED, step.critical))
                ctx.log.info("step", msg=ctx.t("step.skip_dry", step.id))
                continue

            # apply -> verify
            try:
                step.apply()
                ok = step.verify()
            except Exception as exc:
                ctx.log.error("step.apply_error", step=step.id, error=str(exc))
                ok = False

            ctx.state.record_step(step.id, ok, input_hash)
            state_mod.save(ctx.state)  # persist progress after every step

            if ok:
                report.add(StepResult(step.id, Outcome.CHANGED, step.critical))
                ctx.log.info("step", msg=ctx.t("step.applied", step.id))
                continue

            # failure handling
            report.add(StepResult(step.id, Outcome.FAILED, step.critical))
            try:
                step.rollback()
            except Exception as exc:
                ctx.log.error("step.rollback_error", step=step.id, error=str(exc))

            if step.critical:
                ctx.log.error("step", msg=ctx.t("step.critical_abort", step.id))
                report.aborted = True
                raise CriticalStepFailed(step.id)
            ctx.log.warn("step", msg=ctx.t("step.noncritical_warn", step.id))
        return report
