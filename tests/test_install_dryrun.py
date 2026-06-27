from __future__ import annotations

from shroud import orchestrator
from shroud.phases import p0_preflight
from shroud.reconcile import Outcome


def test_dry_run_plans_everything_without_touching_system(ctx, monkeypatch, sandbox):
    # Skip the network-touching preflight; facts are already seeded in fixture.
    monkeypatch.setattr(p0_preflight, "run", lambda c: None)

    report = orchestrator.dry_run(ctx)

    # Nothing converged yet on a fresh sandbox → all actionable steps planned.
    outcomes = {r.step_id: r.outcome for r in report.results}
    assert outcomes["firewall.nftables"] == Outcome.PLANNED
    assert outcomes["hardening.sysctl"] == Outcome.PLANNED
    assert outcomes["stack.compose_up"] == Outcome.PLANNED

    # Dry-run must not write the firewall ruleset or compose file.
    from shroud import paths
    assert not (paths.runtime_dir() / "docker-compose.yml").exists()


def test_standalone_skips_cascade(ctx, monkeypatch):
    monkeypatch.setattr(p0_preflight, "run", lambda c: None)
    ctx.role = "standalone"
    report = orchestrator.dry_run(ctx)
    cascade_steps = [r for r in report.results if r.step_id.startswith("cascade.")]
    assert cascade_steps
    assert all(r.outcome == Outcome.SKIPPED for r in cascade_steps)


def test_entry_requires_exit_bundle_is_planned(ctx, monkeypatch):
    monkeypatch.setattr(p0_preflight, "run", lambda c: None)
    ctx.role = "entry"
    report = orchestrator.dry_run(ctx)
    ids = {r.step_id: r.outcome for r in report.results}
    # entry_wire applicable for entry role, exit_bundle skipped.
    assert ids["cascade.entry_wire"] == Outcome.PLANNED
    assert ids["cascade.exit_bundle"] == Outcome.SKIPPED
