# shroud

Orchestrator that, **with one command**, turns a clean Ubuntu VPS into a hardened
anti-censorship proxy node — modern probe-resistant protocols, a management panel,
a subscription link, and host hardening that won't lock you out.

> Working name: **shroud**. This is the evolution of the earlier single-file bash
> `setup.sh` into a structured, idempotent Python orchestrator (the old script has
> been removed; `bootstrap/setup.sh` is the new thin entrypoint).

## What it deploys

| Layer | Contents |
|-------|----------|
| Host (native) | SSH hardening · nftables firewall (default-deny, ICMP echo drop) · sysctl · fail2ban |
| Proxy stack (Docker Compose) | 3x-ui + xray (**VLESS + Reality + XHTTP**) · **hysteria2** (QUIC) · **telemt** (MTProto, FakeTLS + probe-resistant) · nginx decoy |

Three node roles: **standalone**, **exit** (abroad), **entry** (routes its traffic
into an exit over native xray Reality routing).

## Design in one paragraph

A **stable layer** (this Python code: phases, the `check→apply→verify` reconcile
engine, hardening, cascade, verification) is kept separate from a **volatile layer**
(`profiles/default.yml` — pinned image versions and protocol parameters that rot
upstream every month). Moving to a new "current best" is a profile bump + `shroud
update`, never a code rewrite. Everything is **idempotent** (re-running is a no-op
when converged, a repair when drifted) and **fails safe** (a critical failure stops
with preserved state and never bricks SSH).

## Quick start

```bash
bash <(curl -fsSL https://<host>/setup.sh) -- install --role standalone --mode quick
```

The bootstrap (`bootstrap/setup.sh`, <150 lines of bash) only: checks the OS/arch,
installs the runtime (Python venv + Docker from the official repo), fetches the
code, and hands over to the `shroud` orchestrator. All real logic is in Python.

### Commands

| Command | Purpose |
|---------|---------|
| `install --role <r> --mode <quick\|interactive>` | Full run for the role |
| `dry-run` | Show the change plan, apply nothing |
| `status` | State + container health |
| `verify` | Re-run the Phase 6 self-tests only |
| `update` | Validate a new profile, reconcile only what changed |
| `add-user <name>` | Add a client + issue a subscription |
| `show-sub` | Print the subscription link + panel creds |
| `uninstall` | Tear down the stack (SSH/firewall left intact) |

Flags: `--profile <path|url>`, `--ssh-port`, `--panel-port`, `--exit <bundle>`
(role=entry), `--lang en|ru`, `--strict`, `--yes`, `--verbose`.

## Security posture

- **Panel never faces the internet** (D1): bound to `127.0.0.1`, reached via
  `ssh -L 2053:127.0.0.1:2053 root@<ip>`. The firewall never opens 2053.
- **Reality donor SNI** is chosen by scanning the server's **own subnet/ASN**
  (RealiTLScanner) so the fronted site is co-located; fallback donors are
  same-ASN — never `www.microsoft.com`.
- **Probe resistance**: telemt refuses an unknown-SNI probe like a stock web
  server (or fronts the real donor); hysteria2 reverse-proxies a real site;
  nginx serves a plausible decoy, never a default page.
- **Secrets**: CSPRNG, `chmod 600` files, **never** in logs or state (logs are
  JSON with mandatory redaction; state holds references, not secrets). The only
  place secrets are written in clear is `/root/shroud-credentials.txt` (0600).
- **No call-home** beyond an optional pinned-profile fetch.

> Honest limitation (spec §9.2): Reality masks only the handshake; the behavioural
> layer is what gets you flagged. XHTTP + padding **reduces** detectability but does
> not eliminate behavioural analysis. Protocols that work today may be fingerprinted
> tomorrow — which is exactly why they live in an updatable profile.

## Repository layout

```
bootstrap/setup.sh      thin bash entrypoint
shroud/                 orchestrator package
  cli.py                commands/flags, modes, language
  reconcile.py          check→apply→verify engine, dry-run
  state.py profile.py   state + volatile-profile loading/validation
  context.py log.py     shared context, JSON logging w/ redaction
  phases/               0_preflight … 7_output
  components/           xray_3xui, hysteria2, telemt, nginx, sni
  cascade.py verify.py  connect-info bundle + real handshake self-tests
  render/               jinja templates (telemt.toml, hysteria.yaml, nginx)
  i18n/                 en, ru
profiles/               default.yml + schema.json  (volatile layer)
decoy/                  decoy site content
systemd/                periodic self-test timer
tests/                  pytest suite
```

## Component versions (verified upstream 2026-06-27, pinned in the profile)

| Component | Version | Image |
|-----------|---------|-------|
| 3x-ui (+xray) | v3.4.1 | `ghcr.io/mhsanaei/3x-ui` (digest-pinned) |
| hysteria2 | v2.9.3 | `tobyxdd/hysteria` |
| telemt | 3.4.x | `ghcr.io/telemt/telemt` |
| RealiTLScanner | v0.2.3 | release binary |

> Note on `xtls-rprx-vision`: it is **not** used here. With the XHTTP transport the
> VLESS `flow` must be empty — verified against Xray-core source. Vision is RAW/TCP
> only.

## Development / tests

```bash
pip install -e '.[test]'
pytest -q
```

The suite covers the reconcile contract (converged/changed/failed/critical/dry-run),
profile validation, state round-trip + secret redaction, compose/firewall rendering,
link generation, and the cascade bundle. Live container handshakes require a real
Ubuntu node — see the acceptance criteria in the project spec.
