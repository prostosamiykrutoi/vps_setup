"""Install phases (spec §7). Each module exposes ``steps(ctx) -> list[Step]``
(or a ``run(ctx)`` for non-reconcile phases like preflight/verify/output).
"""
