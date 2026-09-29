# ABOUTME: Orchestrates one issuance: identity, groups, CSR, approval, verification, write, audit.
# ABOUTME: All side effects are injected so the flow is testable without a cluster or root.
import os
from dataclasses import dataclass

from kubeid.certs import IssuedCert, build_csr_pem, generate_key, private_key_pem, verify_issued
from kubeid.identity import User, map_groups, resolve_target
from kubeid.kube import csr_manifest, csr_name
from kubeid.kubeconfig import build_kubeconfig
from kubeid.ttl import resolve_ttl


@dataclass(frozen=True)
class IssueOptions:
    for_user: str | None = None
    groups: tuple[str, ...] | None = None
    ttl: str | None = None
    out: str | None = None


@dataclass(frozen=True)
class IssueResult:
    target: User
    groups: tuple[str, ...]
    csr_name: str
    cert: IssuedCert
    path: str
    ttl_seconds: int


def default_output_path(cluster_name, invoker, target, cwd):
    if target.name == invoker.user.name:
        return os.path.join(target.home, ".kube", "kubeid", f"{cluster_name}.yaml")
    return os.path.join(cwd, f"kubeid-{cluster_name}-{target.name}.yaml")


def issue(options, config, invoker, nss, kube, *, now, suffix, read_file, write_file, audit, cwd):
    # Everything that can be refused locally is checked before touching the cluster.
    target = resolve_target(invoker, options.for_user, config.admin_groups, nss)
    groups = map_groups(target.groups, config.group_map, options.groups)
    ttl_seconds = resolve_ttl(options.ttl, config.default_ttl, config.max_ttl)
    ca_pem = read_file(config.ca_file)
    if options.out:
        path = os.path.normpath(os.path.join(cwd, options.out))
    else:
        path = default_output_path(config.cluster_name, invoker, target, cwd)

    key = generate_key()
    name = csr_name(target.name, now, suffix)
    kube.create_csr(
        csr_manifest(
            name,
            build_csr_pem(key, target.name, groups),
            ttl_seconds,
            requested_by=invoker.user.name,
            issued_for=target.name,
        )
    )
    kube.approve_csr(name)
    cert_pem = kube.wait_for_certificate(name)
    cert = verify_issued(cert_pem, key, target.name, groups)

    kubeconfig = build_kubeconfig(
        config.cluster_name, config.server, ca_pem, target.name, cert_pem, private_key_pem(key)
    )
    write_file(path, kubeconfig.encode("utf-8"))
    audit(
        f"issued user={target.name} groups={','.join(groups)} requested_by={invoker.user.name} "
        f"csr={name} not_after={cert.not_after.isoformat()} path={path}"
    )
    return IssueResult(target, groups, name, cert, path, ttl_seconds)
