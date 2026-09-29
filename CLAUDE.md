# kubeid — project notes for Claude

Assistant name on this project: **Vinz** (as in Vinz Clortho, the Keymaster — this
tool hands out keys).

## What this is

Python CLI that issues short-lived per-engineer Kubernetes client-cert kubeconfigs
via the CSR API, with groups mapped from FreeIPA (via NSS/SSSD). Built for a
small platform team running RKE2/K3s. See README.md and
docs/superpowers/specs/2026-09-29-kubeid-design.md.

## Commands

- `uv run pytest tests/unit tests/integration` — fast loop
- `uv run pytest` — all layers including e2e (needs Docker Desktop running)
- `uv run kubeid --help`

## Rules specific to this codebase

- Security boundary lives in `identity.py`, `cli.py::_load_config`, and `output.py`.
  Any change there needs a test that proves the refusal still happens.
- Everything that can be refused locally must be refused before the first kubectl call.
- Only runtime deps: `cryptography`, `pyyaml`. Talk to the cluster only via `kubectl`.
- Every file starts with two `# ABOUTME:` lines.
- `filterwarnings = error` in pytest config: test output must stay pristine.

## Backlog

Deferred kubeid work lives in ISSUES.md.
