"""shroud — orchestrator for deploying anti-censorship proxy nodes.

The package is split into a *stable* layer (orchestration, reconcile engine,
hardening, cascade, verification — this code) and a *volatile* layer (the
profile under ``profiles/``, which pins component versions and protocol
parameters that change frequently upstream).
"""

__version__ = "0.2.0"
SCHEMA_VERSION = 1
