# ABOUTME: End-to-end tests: the real `kubeid issue` CLI against K3s in Docker (harness in conftest.py).
# ABOUTME: Issued identities are checked with `kubectl auth whoami`, their RBAC with `kubectl auth can-i`.
import base64
import json
import os
import pwd
import stat
import subprocess
import sys
from datetime import timedelta

import pytest
from cryptography import x509


def describe(result):
    return (
        f"command: {' '.join(str(arg) for arg in result.args)}\n"
        f"exit code: {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def kubeid_issue(config_file, out, *args):
    """Run `kubeid issue --config CONFIG ... --out OUT` from the output's directory."""
    return subprocess.run(
        [sys.executable, "-m", "kubeid", "issue", "--config", str(config_file), *args, "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=out.parent,
    )


def kubectl(kubeconfig, *args):
    return subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def whoami(kubeconfig):
    result = kubectl(kubeconfig, "auth", "whoami", "-o", "json")
    assert result.returncode == 0, describe(result)
    return json.loads(result.stdout)["status"]["userInfo"]


def assert_can_i(kubeconfig, expected, *args):
    # can-i exits 1 for "no", so the answer printed on stdout is what gets compared.
    result = kubectl(kubeconfig, "auth", "can-i", *args)
    assert result.stdout.strip() == expected, describe(result)


def client_certificate(kubeconfig):
    result = kubectl(
        kubeconfig,
        "config", "view", "--raw", "--minify", "-o", "jsonpath={.users[0].user.client-certificate-data}",
    )
    assert result.returncode == 0 and result.stdout, describe(result)
    return x509.load_pem_x509_certificate(base64.b64decode(result.stdout))


@pytest.mark.e2e
def test_self_service_kubeconfig_has_invoker_identity_and_mapped_groups(kubeid_cluster, tmp_path):
    out = tmp_path / "self.yaml"

    result = kubeid_issue(kubeid_cluster.config_file, out, "--ttl", "1h")

    assert result.returncode == 0, describe(result)
    assert oct(stat.S_IMODE(out.stat().st_mode)) == oct(0o600)
    user = whoami(out)
    assert user["username"] == pwd.getpwuid(os.getuid()).pw_name
    assert "e2e-viewers" in user["groups"]
    assert "system:authenticated" in user["groups"]
    assert_can_i(out, "yes", "list", "pods", "--all-namespaces")
    assert_can_i(out, "no", "delete", "pods", "-n", "default")
    # The built-in view role deliberately excludes secrets.
    assert_can_i(out, "no", "get", "secrets", "-n", "default")


@pytest.mark.e2e
def test_certificate_lifetime_matches_requested_ttl(kubeid_cluster, tmp_path):
    out = tmp_path / "self.yaml"

    result = kubeid_issue(kubeid_cluster.config_file, out, "--ttl", "1h")

    assert result.returncode == 0, describe(result)
    cert = client_certificate(out)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    # The signer backdates notBefore by 5 minutes to tolerate clock skew, so 1h spans exactly 1h05m.
    assert timedelta(minutes=50) < lifetime <= timedelta(hours=1, minutes=5)


@pytest.mark.e2e
def test_admin_issues_kubeconfig_with_the_target_users_groups(kubeid_cluster, tmp_path):
    if kubeid_cluster.daemon_skip_reason:
        pytest.skip(kubeid_cluster.daemon_skip_reason)
    out = tmp_path / "daemon.yaml"

    result = kubeid_issue(kubeid_cluster.config_file, out, "--for", "daemon")

    assert result.returncode == 0, describe(result)
    user = whoami(out)
    assert user["username"] == "daemon"
    assert "e2e-daemons" in user["groups"]
    assert "e2e-viewers" not in user["groups"]
    assert_can_i(out, "yes", "create", "deployments", "-n", "e2e-ns")
    assert_can_i(out, "no", "create", "deployments", "-n", "default")


@pytest.mark.e2e
def test_requesting_a_group_outside_the_mapped_set_is_refused(kubeid_cluster, tmp_path):
    out = tmp_path / "x.yaml"

    result = kubeid_issue(kubeid_cluster.config_file, out, "--groups", "platform-admin")

    assert result.returncode == 1, describe(result)
    assert "kubeid: error:" in result.stderr
    assert not out.exists()
