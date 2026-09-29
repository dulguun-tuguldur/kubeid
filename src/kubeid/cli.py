# ABOUTME: Command-line entry point: `kubeid issue` and `kubeid rbac`.
# ABOUTME: Wires real dependencies (NSS, kubectl, syslog, filesystem) into the core modules.
import argparse
import os
import pwd
import secrets
import shlex
import shutil
import sys
import syslog
from datetime import datetime, timezone

from kubeid.certs import CertError
from kubeid.config import ConfigError, check_private_file, check_trusted_file, load_config
from kubeid.identity import IdentityError, SystemNSS, resolve_invoker
from kubeid.issue import IssueOptions, issue
from kubeid.kube import KubeError, Kubectl
from kubeid.output import OutputError, write_private_file
from kubeid.rbac import render_yaml
from kubeid.ttl import TTLError, format_duration

DEFAULT_CONFIG = "/etc/kubeid/config.yaml"
# As root, binaries are only looked up here, whatever PATH the caller (or sudo) handed us.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
ERRORS = (CertError, ConfigError, IdentityError, KubeError, OutputError, TTLError, OSError)

# Filesystem seams so tests can simulate root-owned files without patching os globally.
_stat = os.stat
_realpath = os.path.realpath


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
    """The file and every directory above it must be controlled by root alone."""
    check_trusted_file(path, _stat(path))
    directory = os.path.dirname(_realpath(path))
    while True:
        check_trusted_file(directory, _stat(directory))
        parent = os.path.dirname(directory)
        if parent == directory:
            return
        directory = parent


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
    check_private_file(config.issuer_kubeconfig, _stat(config.issuer_kubeconfig))
    _check_trusted(config.ca_file)
    return config


def _kubectl_for(euid):
    """kubectl binary and environment to run it with. As root, neither may come from the caller."""
    if euid != 0:
        return "kubectl", None
    binary = shutil.which("kubectl", path=SAFE_PATH)
    if binary is None:
        raise ConfigError(f"kubectl not found in {SAFE_PATH}")
    _check_trusted(binary)
    return binary, {"PATH": SAFE_PATH, "HOME": pwd.getpwuid(0).pw_dir}


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _printable(text):
    # Arguments are caller-controlled; escape newlines etc. so nobody can forge extra log lines.
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def _audit(message):
    syslog.openlog("kubeid", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, _printable(message))
    syslog.closelog()


def _parse_groups(raw):
    if raw is None:
        return None
    return tuple(g.strip() for g in raw.split(",") if g.strip()) or None


def _issue(args, config, euid):
    nss = SystemNSS()
    invoker = resolve_invoker(euid, os.environ, nss)
    writer_user = invoker.user if euid == 0 else None
    kubectl_binary, kubectl_env = _kubectl_for(euid)
    now = datetime.now(timezone.utc)
    result = issue(
        IssueOptions(for_user=args.for_user, groups=_parse_groups(args.groups), ttl=args.ttl, out=args.out),
        config,
        invoker,
        nss,
        Kubectl(config.issuer_kubeconfig, kubectl=kubectl_binary, env=kubectl_env),
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
    argv = sys.argv[1:] if argv is None else list(argv)
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
        # Refusals are audit events too: a blocked escalation attempt should show up in Graylog.
        caller = os.environ.get("SUDO_UID", "unknown") if euid == 0 else str(euid)
        _audit(f"refused uid={caller} args={shlex.join(argv)} error={err}")
        return 1
