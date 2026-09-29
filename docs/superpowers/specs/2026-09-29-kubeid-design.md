# kubeid — design

Date: 2026-09-29. Status: approved in chat (both modes).

## Problem

Engineers SSH to a VM with their personal FreeIPA account, then switch to a shared
Linux user that owns an admin kubeconfig. The Kubernetes audit log only ever sees
that shared identity. Goal: every kubectl action attributable to one person, with
authorization driven by FreeIPA group membership.

## Solution summary

`kubeid` issues short-lived per-engineer kubeconfigs using the Kubernetes CSR API
(`certificates.k8s.io/v1`, signer `kubernetes.io/kube-apiserver-client`).
Certificate subject: `CN=<username>`, one `O=<k8s group>` per mapped group.
RBAC binds Kubernetes groups, not users. `kubeid rbac` renders those bindings
from the same config so Git stays the single source of truth.

## Modes

### Self-service (primary)

```
engineer SSH (FreeIPA) -> jump host
$ sudo kubeid issue [--ttl 12h] [--groups g1,g2] [--out PATH]
```

- Identity = `SUDO_UID` resolved via NSS. Root without `SUDO_UID` is refused
  (root has no personal identity). `SUDO_UID=0` is refused.
- Groups = NSS groups of the user (SSSD -> FreeIPA) mapped through the config
  allowlist. Unmapped groups are ignored. No mapped group = refused.
- `--groups` can only narrow the mapped set.
- Output default: `~<user>/.kube/kubeid/<cluster>.yaml`.

### Admin issuing for someone else

```
$ sudo kubeid issue --for alice [--ttl 12h] [--groups ...] [--out PATH]
```

- Invoker must be a member of a Linux group listed in `policy.admin_groups`.
- Target groups still come from the target's FreeIPA membership (NSS).
  An admin delivers credentials; an admin cannot grant groups the target lacks.
- Output default: `./kubeid-<cluster>-<target>.yaml`, owned by the invoker.
  Deliver via Infisical, never chat.

### Non-sudo invocation

A non-root user who can read the issuer kubeconfig (e.g. admin on own machine)
runs `kubeid issue` directly. Identity = current uid. Same rules otherwise.

## Security rules

1. Under sudo, `--config` is rejected; config path is fixed
   (`/etc/kubeid/config.yaml`). Otherwise a user supplies their own group mapping.
2. When running as root, the config file must be root-owned and not
   group/world-writable.
3. Output file is written by a forked child that drops to the invoker's
   uid/gid/groups. Symlink tricks only reach files the invoker could already write.
4. Usernames must match `^[a-z_][a-z0-9_.-]{0,63}$`. Kubernetes group names must
   match `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`. Both forbid `system:` by construction.
5. TTL parsed from `<n>m|h|d`, must be within `[10m, policy.max_ttl]`
   (Kubernetes minimum `expirationSeconds` is 600). Out of range = error, not clamp.
6. Issued certificate is verified before writing: CN, set of O, and public key
   must match what was requested.
7. Every issuance is logged to syslog (`LOG_AUTH`) for Graylog.

Known limits (accepted):
- Kubernetes cannot revoke client certificates. Short TTL (default 12h, max 24h)
  is the control. Removing a user from a FreeIPA group takes effect at next renewal.
  Emergency levers: delete the group binding, or rotate the client CA.
- The issuer kubeconfig can mint any identity. Treat it like a CA key: root-only
  0600 on the jump host. Its ServiceAccount token is revocable (delete the Secret).

## Config (`/etc/kubeid/config.yaml`)

```yaml
cluster:
  name: prod
  server: https://10.10.0.10:6443      # kube-vip VIP
  ca_file: /etc/kubeid/prod-ca.crt     # API server CA, embedded in issued kubeconfigs
issuer:
  kubeconfig: /etc/kubeid/issuer.kubeconfig
policy:
  default_ttl: 12h
  max_ttl: 24h
  admin_groups: [k8s-platform-admin]   # Linux/FreeIPA groups allowed to use --for
groups:                                # Linux/FreeIPA group -> Kubernetes group
  k8s-platform-admin: platform-admin
  k8s-senior-dev: cluster-viewer
  k8s-loans-dev: loans-edit
rbac:
  - group: platform-admin
    clusterrole: cluster-admin
  - group: cluster-viewer
    clusterrole: view
  - group: loans-edit
    clusterrole: edit
    namespaces: [loans-dev, loans-stg]
```

## Commands

- `kubeid issue [--for USER] [--groups G1,G2] [--ttl 12h] [--out PATH] [--config PATH]`
- `kubeid rbac [--config PATH]` — prints YAML: namespace `kubeid`, ServiceAccount
  `kubeid-issuer`, token Secret, ClusterRole `kubeid:issuer`, its binding, and one
  ClusterRoleBinding/RoleBinding per `rbac` entry.

Exit code 0 on success, 1 on any error (`kubeid: error: ...` on stderr).

## Issue flow

1. Load + validate config. Resolve invoker. Resolve target (self or `--for`).
2. Map target groups. Apply `--groups` narrowing. Parse TTL.
3. Generate EC P-256 key + CSR.
4. `kubectl --kubeconfig <issuer> create -f -` (CSR JSON, annotations
   `kubeid/requested-by`, `kubeid/issued-for`).
5. `kubectl certificate approve <name>`, poll `get csr <name> -o json` for
   `status.certificate` (timeout 30s; Denied/Failed condition = error).
6. Verify certificate. Build kubeconfig. Write as invoker, mode 0600.
7. Syslog line. Print summary + `kubectl --kubeconfig <path> auth whoami`.

## Architecture

```
src/kubeid/
  cli.py         argparse, wires real dependencies, prints output
  config.py      YAML load + validation -> Config dataclass
  identity.py    invoker/target resolution, group mapping, authorization rules
  ttl.py         duration parsing + bounds
  certs.py       key/CSR generation, issued-cert verification (cryptography)
  kube.py        kubectl subprocess adapter (create/approve/wait CSR)
  kubeconfig.py  kubeconfig document
  rbac.py        RBAC manifest rendering
  output.py      private file writer (privilege-dropping when root)
  issue.py       orchestration, dependencies injected
```

Runtime deps: `cryptography`, `pyyaml`. Talks to the cluster only via `kubectl`.

## Testing

- Unit: ttl, config validation, identity rules, group mapping, CSR subject,
  kubeconfig and RBAC rendering, cert verification.
- Integration: full `kubeid issue` CLI run against a stub `kubectl` executable
  that signs CSRs with a throwaway CA; checks file mode, kubeconfig content,
  cert validity, and the exact kubectl calls.
- E2E: real K3s in Docker. Apply `kubeid rbac`, build issuer kubeconfig from the
  ServiceAccount token, `kubeid issue`, then `kubectl auth whoami` shows the
  user + groups and `kubectl auth can-i` matches the bindings.

## Out of scope (for now)

Teleport Kubernetes access, OIDC, audit policy tuning (doc snippet only),
per-user RBAC subjects, automatic renewal.
