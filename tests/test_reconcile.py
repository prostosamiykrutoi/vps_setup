from __future__ import annotations

import pytest

from shroud.reconcile import (CriticalStepFailed, Engine, Outcome, Step)


class Recorder:
    def __init__(self):
        self.applied = 0


def make_step(ctx, *, converged, verify_ok=True, critical=False, rec=None,
              step_id="s"):
    class _S(Step):
        id = step_id

    s = _S(ctx)
    s.critical = critical
    s._converged = converged

    def check():
        return s._converged

    def apply():
        if rec:
            rec.applied += 1
        s._converged = True  # simulate convergence after apply

    def verify():
        return verify_ok

    s.check = check
    s.apply = apply
    s.verify = verify
    return s


def test_converged_step_is_noop(ctx):
    rec = Recorder()
    s = make_step(ctx, converged=True, rec=rec)
    report = Engine(ctx).run([s])
    assert report.results[0].outcome == Outcome.CONVERGED
    assert rec.applied == 0


def test_drifted_step_is_applied(ctx):
    rec = Recorder()
    ctx.dry_run = False
    ctx.runner.dry_run = False
    s = make_step(ctx, converged=False, rec=rec)
    report = Engine(ctx).run([s])
    assert report.results[0].outcome == Outcome.CHANGED
    assert rec.applied == 1


def test_dry_run_plans_without_applying(ctx):
    rec = Recorder()
    s = make_step(ctx, converged=False, rec=rec)
    report = Engine(ctx).run([s])  # ctx.dry_run is True in fixture
    assert report.results[0].outcome == Outcome.PLANNED
    assert rec.applied == 0


def test_noncritical_verify_failure_continues(ctx):
    ctx.dry_run = False
    s1 = make_step(ctx, converged=False, verify_ok=False, critical=False,
                   step_id="bad")
    s2 = make_step(ctx, converged=True, step_id="good")
    report = Engine(ctx).run([s1, s2])
    assert report.results[0].outcome == Outcome.FAILED
    assert report.results[1].outcome == Outcome.CONVERGED
    assert not report.aborted


def test_critical_verify_failure_aborts(ctx):
    ctx.dry_run = False
    s1 = make_step(ctx, converged=False, verify_ok=False, critical=True,
                   step_id="crit")
    with pytest.raises(CriticalStepFailed):
        Engine(ctx).run([s1])


def test_inapplicable_step_skipped(ctx):
    s = make_step(ctx, converged=False)
    s.applicable = lambda: False
    report = Engine(ctx).run([s])
    assert report.results[0].outcome == Outcome.SKIPPED
