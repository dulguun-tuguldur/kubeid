# ABOUTME: Integration tests: run the real kubeid CLI as a subprocess against a stub kubectl.
# ABOUTME: Exercises real NSS lookups, crypto, file permissions and the exact kubectl call sequence.
import base64
import getpass
import grp
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from testca import cert_to_pem, key_to_pem, make_ca

STUB = Path(__file__).parent / "stub_kubectl.py"


def daemon_user():
    try:
        return pwd.getpwnam("daemon")
    except KeyError:
        pytest.skip("host has no 'daemon' user to use as --for target")


@pytest.fixture
def env(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    ca_key, ca_cert = make_ca()
    (state / "ca.key").write_bytes(key_to_pem(ca_key))
    (state / "ca.crt").write_bytes(cert_to_pem(ca_cert))

    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "kubectl"
    stub.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{STUB}" "$@"\n')
    stub.chmod(0o755)

    my_group = grp.getgrgid(os.getgid()).gr_name
    groups = {my_group: "it-viewers"}
    try:
        daemon_group = grp.getgrgid(pwd.getpwnam("daemon").pw_gid).gr_name
        groups[daemon_group] = "it-daemons"
    except KeyError:
        pass
    issuer = tmp_path / "issuer.kubeconfig"
    config = {
        "cluster": {"name": "it", "server": "https://stub.invalid:6443", "ca_file": str(state / "ca.crt")},
        "issuer": {"kubeconfig": str(issuer)},
        "policy": {"default_ttl": "12h", "max_ttl": "24h", "admin_groups": [my_group]},
        "groups": groups,
        "rbac": [{"group": "it-viewers", "clusterrole": "view"}],
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "kubeid", *args],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            timeout=60,
            env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "STUB_KUBECTL_STATE": str(state)},
        )

    def calls():
        path = state / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    return SimpleNamespace(
        tmp=tmp_path, state=state, ca_cert=ca_cert, config=str(config_path), issuer=str(issuer), run=run, calls=calls
    )


def load_credentials(path):
    doc = yaml.safe_load(Path(path).read_text())
    user = doc["users"][0]["user"]
    cert = x509.load_pem_x509_certificate(base64.b64decode(user["client-certificate-data"]))
    key = serialization.load_pem_private_key(base64.b64decode(user["client-key-data"]), password=None)
    return doc, cert, key


def subject(cert, oid):
    return [a.value for a in cert.subject.get_attributes_for_oid(oid)]


def test_self_issue_writes_valid_private_kubeconfig(env):
    out = env.tmp / "creds" / "self.yaml"
    proc = env.run("issue", "--config", env.config, "--ttl", "1h", "--out", "creds/self.yaml")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert str(out) in proc.stdout
    assert f"kubectl --kubeconfig {out} auth whoami" in proc.stdout
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600

    doc, cert, key = load_credentials(out)
    assert doc["clusters"][0]["cluster"]["server"] == "https://stub.invalid:6443"
    assert base64.b64decode(doc["clusters"][0]["cluster"]["certificate-authority-data"]) == cert_to_pem(env.ca_cert)
    env.ca_cert.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
    )
    assert subject(cert, NameOID.COMMON_NAME) == [getpass.getuser()]
    assert subject(cert, NameOID.ORGANIZATION_NAME) == ["it-viewers"]
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    lifetime = (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds()
    assert 3600 <= lifetime <= 3600 + 300


def test_issue_runs_create_approve_get_against_issuer_kubeconfig(env):
    proc = env.run("issue", "--config", env.config, "--out", "x.yaml")
    assert proc.returncode == 0, proc.stderr
    calls = env.calls()
    assert [c[:2] for c in calls] == [["--kubeconfig", env.issuer]] * 3
    name = calls[1][4]
    assert [c[2:] for c in calls] == [
        ["create", "-f", "-"],
        ["certificate", "approve", name],
        ["get", "csr", name, "-o", "json"],
    ]
    manifest = json.loads((env.state / f"csr-{name}.json").read_text())
    assert manifest["spec"]["expirationSeconds"] == 12 * 3600


def test_admin_issue_for_other_user(env):
    target = daemon_user()
    proc = env.run("issue", "--config", env.config, "--for", target.pw_name)
    assert proc.returncode == 0, proc.stderr
    out = env.tmp / f"kubeid-it-{target.pw_name}.yaml"
    assert str(out) in proc.stdout
    assert "Infisical" in proc.stdout
    _, cert, _ = load_credentials(out)
    assert subject(cert, NameOID.COMMON_NAME) == [target.pw_name]
    assert subject(cert, NameOID.ORGANIZATION_NAME) == ["it-daemons"]
    (csr_file,) = env.state.glob("csr-*.json")
    annotations = json.loads(csr_file.read_text())["metadata"]["annotations"]
    assert annotations == {"kubeid/requested-by": getpass.getuser(), "kubeid/issued-for": target.pw_name}


def test_denied_csr_fails_and_writes_nothing(env):
    (env.state / "deny").touch()
    proc = env.run("issue", "--config", env.config, "--out", "denied.yaml")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert proc.stderr.startswith("kubeid: error: CSR kubeid-")
    assert "Denied: StubDenied: denied by stub" in proc.stderr
    assert not (env.tmp / "denied.yaml").exists()


def test_ttl_above_policy_fails_before_any_kubectl_call(env):
    proc = env.run("issue", "--config", env.config, "--ttl", "48h", "--out", "x.yaml")
    assert proc.returncode == 1
    assert proc.stderr == "kubeid: error: ttl 48h exceeds policy max_ttl 24h\n"
    assert env.calls() == []


def test_group_narrowing_to_ungranted_group_fails(env):
    proc = env.run("issue", "--config", env.config, "--groups", "platform-admin", "--out", "x.yaml")
    assert proc.returncode == 1
    assert "not granted by group membership: platform-admin" in proc.stderr
    assert env.calls() == []


def test_rbac_prints_applyable_manifests(env):
    proc = env.run("rbac", "--config", env.config)
    assert proc.returncode == 0, proc.stderr
    docs = [d for d in yaml.safe_load_all(proc.stdout) if d]
    names = {(d["kind"], d["metadata"]["name"]) for d in docs}
    assert ("ClusterRole", "kubeid:issuer") in names
    assert ("ClusterRoleBinding", "kubeid:it-viewers:view") in names


def test_invalid_config_fails_with_clear_error(env):
    Path(env.config).write_text("cluster: {}\npolcy: {}\n")
    proc = env.run("issue", "--config", env.config)
    assert proc.returncode == 1
    assert proc.stderr == "kubeid: error: unknown key 'polcy' in config\n"


def test_missing_default_config_is_reported(env):
    if os.path.exists("/etc/kubeid/config.yaml"):
        pytest.skip("host has a real /etc/kubeid/config.yaml")
    proc = env.run("issue")
    assert proc.returncode == 1
    assert proc.stderr.startswith("kubeid: error: cannot read config /etc/kubeid/config.yaml")
