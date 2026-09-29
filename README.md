# kubeid

Short-lived, per-engineer Kubernetes credentials whose identity comes from FreeIPA.

Replaces "SSH in as yourself, then switch to the shared user that owns the admin
kubeconfig". Every kubectl action is attributed to a person in the API server audit
log, and access follows FreeIPA group membership.

```
engineer (FreeIPA login) ── ssh ──> jump host
  $ sudo kubeid issue
      identity  = SUDO_UID            (set by sudo, not spoofable by the caller)
      groups    = SSSD groups ∩ config allowlist   (k8s-loans-dev -> loans-edit)
      key + CSR = EC P-256, CN=<user>, O=<group>...
      kubectl --kubeconfig /etc/kubeid/issuer.kubeconfig
          create CSR (signer kubernetes.io/kube-apiserver-client, expirationSeconds=TTL)
          certificate approve, wait for status.certificate
      verify    = issued CN / O / public key == requested
      write     = ~/.kube/kubeid/<cluster>.yaml, 0600, written *as the engineer*
      syslog    = LOG_AUTH line for Graylog
  $ export KUBECONFIG=~/.kube/kubeid/prod.yaml
  $ kubectl auth whoami        # Username: alice, Groups: [loans-edit system:authenticated]
```

## Commands

```
kubeid issue [--ttl 12h] [--groups g1,g2] [--out PATH]      # for yourself
kubeid issue --for USER [--ttl ...] [--out PATH]             # admins (policy.admin_groups)
kubeid rbac                                                  # print RBAC YAML for Git + kubectl apply
```

- `--groups` only narrows what FreeIPA membership grants. It can never add a group.
- `--for` needs membership in `policy.admin_groups`. The target's groups still come
  from the target's own FreeIPA membership, so an admin delivers credentials but
  cannot grant extra access. Output goes to `./kubeid-<cluster>-<user>.yaml`, owned
  by the admin. Hand it over through Infisical, never chat.
- `--ttl` must be within `[10m, policy.max_ttl]`. Out of range is an error, not a clamp.
- As root (i.e. under sudo) `--config` is refused and the config, issuer kubeconfig
  and CA file (plus their directories) must be root-owned and not group/world-writable.

Exit code 0 on success, 1 on any error (`kubeid: error: ...` on stderr).

## Rollout (Before / Change / Verify / Rollback)

Nothing below changes existing access. The shared user keeps working until phase 3.

### Before — pre-flight on one RKE2 server node

```bash
# RKE2 server node: CSR signer for client certs must be the CA the API server trusts
ps -ef | grep -o -- '--cluster-signing-kube-apiserver-client-cert-file=[^ ]*' | head -1
ps -ef | grep -o -- '--client-ca-file=[^ ]*' | head -1
ps -ef | grep -o -- '--cluster-signing-duration=[^ ]*' | head -1   # empty = 1y default
```

Expected: both paths point at `/var/lib/rancher/rke2/server/tls/client-ca.crt`
(K3s: `/var/lib/rancher/k3s/server/tls/client-ca.crt`). If `--cluster-signing-duration`
is shorter than `max_ttl`, certs silently get the shorter lifetime.

### Change 1 — RBAC (additive)

`kubeid rbac` does not create the target namespaces of namespaced rules
(`loans-dev`, ...). They must already exist, or `kubectl apply` fails on those RoleBindings.

```bash
# workstation, in the infra Git repo
kubeid rbac --config ./kubeid/config.yaml > ./kubeid/rbac.yaml
git add kubeid/ && git commit -m "kubeid: issuer + group bindings"
kubectl --context prod apply -f ./kubeid/rbac.yaml
kubectl --context prod -n kubeid get secret kubeid-issuer-token -o jsonpath='{.data.token}' | wc -c   # > 0
```

### Change 2 — install on the jump host (as root)

The file writer runs as the engineer, so the interpreter and venv must be
world-readable. Do not install into `/root`.

```bash
# jump host
sudo env UV_PYTHON_INSTALL_DIR=/opt/uv/python UV_TOOL_DIR=/opt/uv/tools UV_TOOL_BIN_DIR=/usr/local/bin \
  uv tool install /srv/src/kubeid
ls -l /usr/local/bin/kubeid

sudo install -d -m 0755 -o root -g root /etc/kubeid
sudo install -m 0644 -o root -g root prod-ca.crt /etc/kubeid/prod-ca.crt   # API server CA (server-ca.crt on RKE2)
sudo install -m 0644 -o root -g root config.yaml /etc/kubeid/config.yaml
```

Issuer kubeconfig. The token travels via stdin, never argv (argv is visible in `ps`):

```bash
# jump host, with your current admin access
TOKEN=$(kubectl --context prod -n kubeid get secret kubeid-issuer-token -o jsonpath='{.data.token}' | base64 -d)
CA_B64=$(base64 -w0 /etc/kubeid/prod-ca.crt)
sudo sh -c 'umask 077; cat > /etc/kubeid/issuer.kubeconfig' <<EOF
apiVersion: v1
kind: Config
clusters: [{name: prod, cluster: {server: "https://10.10.0.10:6443", certificate-authority-data: "$CA_B64"}}]
users: [{name: kubeid-issuer, user: {token: "$TOKEN"}}]
contexts: [{name: prod, context: {cluster: prod, user: kubeid-issuer}}]
current-context: prod
EOF
unset TOKEN
sudo ls -l /etc/kubeid/issuer.kubeconfig    # -rw------- root root
```

### Change 3 — FreeIPA sudo rule

```bash
ipa sudocmd-add /usr/local/bin/kubeid
ipa sudorule-add kubeid
ipa sudorule-add-allow-command kubeid --sudocmds=/usr/local/bin/kubeid
ipa sudorule-add-host kubeid --hosts=jump01.example.internal
ipa sudorule-add-user kubeid --groups=k8s-platform-admin --groups=k8s-senior-dev --groups=k8s-loans-dev
# the HBAC rule for those groups on the jump host must also allow the 'sudo' service
```

Do not grant `SETENV` on this rule. kubeid trusts `SUDO_UID`, which sudo sets itself.
Allow only the installed entry point, never `python -m kubeid` (that imports from cwd).

### Verify

```bash
# jump host, as an engineer
sudo kubeid issue
export KUBECONFIG=~/.kube/kubeid/prod.yaml
kubectl auth whoami                  # your username + mapped groups
kubectl auth can-i --list | head     # matches the group's role
journalctl -t kubeid --since today   # issuance audit line (syslog LOG_AUTH)
```

API server audit log should show `user.username=<you>` for your requests (see Audit below).

### Rollback

```bash
kubectl --context prod delete -f ./kubeid/rbac.yaml   # removes issuer + all kubeid bindings
ipa sudorule-del kubeid
sudo rm -rf /etc/kubeid && sudo uv tool uninstall kubeid
```

Deleting the bindings immediately strips authorization from every kubeid-issued
cert, even though the certs themselves stay valid until expiry. Deleting the
`kubeid-issuer-token` Secret immediately kills the issuer credential.

### Phase 3 — retire the shared user (separate change)

Only after everyone has used kubeid for a while: remove the kubeconfig from the
shared Linux user. If that kubeconfig is a copy of `rke2.yaml` it is a
`system:masters` client cert: RBAC cannot revoke it. Killing it means rotating RKE2
certificates (`rke2 certificate rotate`, one server at a time, planned window).

## Audit logging (RKE2)

Illustrative; check the RKE2 docs for your version before applying. Restarting
`rke2-server` restarts the control plane on that node, so roll one server at a time.

```yaml
# /etc/rancher/rke2/config.yaml (server nodes)
audit-policy-file: /etc/rancher/rke2/audit-policy.yaml
kube-apiserver-arg:
  - audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log
  - audit-log-maxage=30
  - audit-log-maxbackup=10
  - audit-log-maxsize=100
```

```yaml
# /etc/rancher/rke2/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: None
    nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/version"]
  - level: None
    users: ["system:kube-proxy"]
  - level: Metadata
```

Ship `audit.log` to Graylog; filter on `user.username` and `user.groups`.

## Security model and known limits

- **Issuer kubeconfig = CA-grade secret.** Its token can create and approve
  client-cert CSRs for any name and group, including admin groups. kubeid refuses
  `system:*` and anything outside the allowlist, but raw kubectl with that file would
  not. Keep it root-only on the jump host. Revoke by deleting its Secret.
- **Client certs cannot be revoked by Kubernetes.** Short TTL is the control. Removing
  someone from a FreeIPA group takes effect at their next renewal (≤ TTL).
  Immediate levers: delete the relevant group binding (affects the whole group),
  or delete all kubeid bindings (rollback above).
- **Root on the jump host is the trust boundary.** Anyone with unrestricted sudo
  there can read the issuer kubeconfig. Engineers should only be allowed
  `/usr/local/bin/kubeid`.
- Output is written by a child process that runs as the invoker (uid, gid,
  supplementary groups, umask 077) using temp file + rename, so a symlink at the
  output path can never redirect a root write.
- Longer term, Teleport Kubernetes access (if you run Teleport) gives the same
  attribution plus session recording and revocable short-lived certs. kubeid is the
  low-friction step that gets attribution now.

## Development

```bash
uv run pytest tests/unit tests/integration   # fast loop, ~5s
uv run pytest                                # everything, including e2e (needs Docker)
```

- `tests/unit` — pure logic with fakes.
- `tests/integration` — the real CLI as a subprocess against a stub `kubectl` that
  signs CSRs with a throwaway CA.
- `tests/e2e` — real K3s in Docker: apply `kubeid rbac`, issue, `kubectl auth whoami`,
  `kubectl auth can-i`.
- `tests/e2e_sudo` — Debian container with real `sudo` and FreeIPA-like users/groups
  (stub kubectl): identity from `SUDO_UID`, output owned by the invoker, symlink at the
  output path cannot touch `/etc/shadow`, and every root-only refusal (`--config`,
  writable config, user-owned issuer kubeconfig, bare root, non-admin `--for`,
  group escalation).

Design: `docs/superpowers/specs/2026-09-29-kubeid-design.md`. Other tool ideas: `IDEAS.md`.
