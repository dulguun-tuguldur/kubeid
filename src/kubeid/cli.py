# ABOUTME: Command-line entry point: `kubeid issue` and `kubeid rbac`.
# ABOUTME: Wires real dependencies (NSS, kubectl, syslog, filesystem) into the core modules.
import argparse
import os
import secrets
import sys
import syslog
from datetime import datetime, timezone

from kubeid.certs import CertError
from kubeid.config import ConfigError, check_trusted_file, load_config
from kubeid.identity import IdentityError, SystemNSS, resolve_invoker
from kubeid.issue import IssueOptions, issue
from kubeid.kube import KubeError, Kubectl
from kubeid.output import OutputError, write_private_file
from kubeid.rbac import render_yaml
from kubeid.ttl import TTLError, format_duration

DEFAULT_CONFIG = "/etc/kubeid/config.yaml"
ERRORS = (CertError, ConfigError, IdentityError, KubeError, OutputError, TTLError, OSError)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="kubeid", description="Issue short-lived per-engineer Kubernetes credentials."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    issue_p = sub.add_parser("issue", help="issue a kubeconfig for yourself, or --for someone (admins)")
    issue_p.add_argument("--for", dest="for_user", metavar="USER",
                         help="issue for another user (requires policy.admin_groups membership)")
    issue_p.add_argument("--groups", help="comma-separated subset of your mapped Kubernetes groups")
    issue_p.add_argument("--ttl", help="lifetime such as 30m, 12h, 1d (default: policy.default_ttl)")
    issue_p.add_argument("--out", help="output path (default: ~/.kube/kubeid/<cluster>.yaml, "
                                       "or ./kubeid-<cluster>-<user>.yaml with --for)")
    issue_p.add_argument("--config", help=f"config path (default {DEFAULT_CONFIG}; not allowed as root)")

    rbac_p = sub.add_parser("rbac", help="print RBAC manifests (issuer + group bindings) as YAML")
    rbac_p.add_argument("--config", help=f"config path (default {DEFAULT_CONFIG}; not allowed as root)")
    return parser


def _check_trusted(path):
    check_trusted_file(path, os.stat(path))
    parent = os.path.dirname(os.path.realpath(path))
    check_trusted_file(parent, os.stat(parent))


def _load_config(args, euid):
    if euid != 0:
        return load_config(args.config or DEFAULT_CONFIG)
    # As root, a caller-chosen config could map their own group to cluster-admin,
    # and a writable issuer kubeconfig could run an exec plugin as root.
    if args.config is not None:
        raise ConfigError(f"--config is not allowed when running as root; kubeid always reads {DEFAULT_CONFIG}")
    _check_trusted(DEFAULT_CONFIG)
    config = load_config(DEFAULT_CONFIG)
    _check_trusted(config.issuer_kubeconfig)
    _check_trusted(config.ca_file)
    return config


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _audit(message):
    syslog.openlog("kubeid", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, message)
    syslog.closelog()


def _parse_groups(raw):
    if raw is None:
        return None
    return tuple(g.strip() for g in raw.split(",") if g.strip()) or None


def _issue(args, config, euid):
    nss = SystemNSS()
    invoker = resolve_invoker(euid, os.environ, nss)
    writer_user = invoker.user if euid == 0 else None
    now = datetime.now(timezone.utc)
    result = issue(
        IssueOptions(for_user=args.for_user, groups=_parse_groups(args.groups), ttl=args.ttl, out=args.out),
        config,
        invoker,
        nss,
        Kubectl(config.issuer_kubeconfig),
        now=now,
        suffix=secrets.token_hex(2),
        read_file=_read_bytes,
        write_file=lambda path, data: write_private_file(path, data, writer_user),
        audit=_audit,
        cwd=os.getcwd(),
    )
    expires = result.cert.not_after.strftime("%Y-%m-%d %H:%M UTC")
    print(f"✓ identity   {result.target.name}  (requested by {invoker.user.name})")
    print(f"✓ groups     {', '.join(result.groups)}")
    print(f"✓ csr        {result.csr_name} approved and issued")
    print(f"✓ cert       CN={result.target.name} O={','.join(result.groups)}  "
          f"expires {expires} ({format_duration(result.ttl_seconds)})")
    print(f"✓ kubeconfig {result.path} (0600)")
    print()
    if result.target.name != invoker.user.name:
        print(f"deliver: store in Infisical for {result.target.name}; never paste kubeconfigs in chat")
    print(f"use:     export KUBECONFIG={result.path}")
    print(f"verify:  kubectl --kubeconfig {result.path} auth whoami")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    euid = os.geteuid()
    try:
        config = _load_config(args, euid)
        if args.command == "rbac":
            sys.stdout.write(render_yaml(config))
            return 0
        return _issue(args, config, euid)
    except ERRORS as err:
        print(f"kubeid: error: {err}", file=sys.stderr)
        return 1
