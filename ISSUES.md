# Open issues

Noticed while building/reviewing kubeid; deliberately not fixed yet.

## 1. K3s cluster CA has serial number 0

`cryptography` 50 emits a deprecation warning when parsing such a cert and says a
future release will refuse it. kubeid never parses `ca_file` (it embeds the bytes),
so nothing breaks today. If CA validation is ever added (e.g. check that `ca_file`
actually verifies the API server), handle this or it will break against K3s.
Source: K3s e2e harness work, 2026-09-29.

## 2. Signer can silently shorten the certificate lifetime

If kube-controller-manager runs with `--cluster-signing-duration` shorter than the
requested TTL, the cert is shorter than asked. kubeid prints the real expiry but
does not warn. Consider a warning when `not_after` < requested by more than the
5-minute backdate.

## 3. No immediate single-user revocation

Bindings are per group, and client certs cannot be revoked. Cutting off one person
right now means deleting their whole group's binding, or waiting for TTL. Options:
per-user bindings rendered from FreeIPA membership (adds sync), or move this use
case to Teleport Kubernetes access (revocable, session-recorded).

## 4. Python 3.12 required

`requires-python >= 3.12`. Ubuntu 22.04 ships 3.10, so install with a uv-managed
interpreter under `/opt` (README shows how). Lowering to 3.10 looks feasible (no 3.11+
syntax is used), but the suite has not been run on 3.10 yet.
