# ABOUTME: E2E tests of the self-service path under real sudo in a Linux container.
# ABOUTME: Proves SUDO_UID identity, privilege-dropped writes, and every root-only refusal.
import base64
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[2]
MARK = "---FILE---"


@pytest.fixture(scope="module")
def image():
    tag = f"kubeid-e2e-sudo:{uuid.uuid4().hex[:8]}"
    build = subprocess.run(
        ["docker", "build", "-q", "-t", tag, "-f", str(REPO / "tests/e2e_sudo/Dockerfile"), str(REPO)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert build.returncode == 0, build.stderr
    yield tag
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, timeout=120)


def run(image, script):
    return subprocess.run(
        ["docker", "run", "--rm", image, "bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
    )


def as_user(user, command):
    return f"su - {user} -c {command!r}"


def cert_from(stdout):
    doc = yaml.safe_load(stdout.split(MARK, 1)[1])
    pem = base64.b64decode(doc["users"][0]["user"]["client-certificate-data"])
    cert = x509.load_pem_x509_certificate(pem)
    cn = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    orgs = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    return cn, orgs


@pytest.mark.e2e
def test_self_service_writes_owned_private_kubeconfig(image):
    path = "/home/alice/.kube/kubeid/e2e.yaml"
    proc = run(image, f"{as_user('alice', 'sudo kubeid issue')} && stat -c '%U %a' {path} && echo {MARK} && cat {path}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "alice 600" in proc.stdout
    assert cert_from(proc.stdout) == (["alice"], ["loans-edit"])


@pytest.mark.e2e
def test_symlink_at_output_path_cannot_redirect_root_write(image):
    path = "/home/alice/.kube/kubeid/e2e.yaml"
    script = (
        "before=$(sha256sum /etc/shadow) && "
        + as_user("alice", f"mkdir -p ~/.kube/kubeid && ln -s /etc/shadow {path} && sudo kubeid issue")
        + f' && [ "$before" = "$(sha256sum /etc/shadow)" ] && echo SHADOW-UNCHANGED'
        + f" && [ ! -L {path} ] && stat -c '%U %a' {path}"
    )
    proc = run(image, script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SHADOW-UNCHANGED" in proc.stdout
    assert "alice 600" in proc.stdout


@pytest.mark.e2e
def test_out_path_is_written_with_invokers_permissions(image):
    proc = run(image, as_user("alice", "sudo kubeid issue --out /etc/kubeid/pwned.yaml") + "; echo rc=$?; ls /etc/kubeid")
    assert "rc=1" in proc.stdout
    assert "kubeid: error: writing /etc/kubeid/pwned.yaml as alice failed: Permission denied" in proc.stderr
    assert "pwned.yaml" not in proc.stdout


@pytest.mark.e2e
def test_admin_issues_for_someone_else_into_own_directory(image):
    path = "/home/bob/kubeid-e2e-alice.yaml"
    proc = run(image, f"{as_user('bob', 'sudo kubeid issue --for alice')} && stat -c '%U %a' {path} && echo {MARK} && cat {path}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "bob 600" in proc.stdout
    assert "deliver: store in Infisical for alice" in proc.stdout
    assert cert_from(proc.stdout) == (["alice"], ["loans-edit"])


@pytest.mark.e2e
@pytest.mark.parametrize(
    "script,expected",
    [
        (as_user("alice", "sudo kubeid issue --config /home/alice/evil.yaml"),
         "kubeid: error: --config is not allowed when running as root"),
        (as_user("alice", "sudo kubeid issue --for bob"),
         "kubeid: error: --for requires membership in one of: k8s-platform-admin"),
        (as_user("alice", "sudo kubeid issue --groups platform-admin"),
         "kubeid: error: requested groups not granted by group membership: platform-admin"),
        (as_user("mallory", "sudo kubeid issue"),
         "kubeid: error: no Kubernetes groups mapped"),
        ("chmod 0666 /etc/kubeid/config.yaml && " + as_user("alice", "sudo kubeid issue"),
         "kubeid: error: /etc/kubeid/config.yaml is group/world-writable"),
        ("chmod 0640 /etc/kubeid/issuer.kubeconfig && chown alice /etc/kubeid/issuer.kubeconfig && "
         + as_user("alice", "sudo kubeid issue"),
         "kubeid: error: /etc/kubeid/issuer.kubeconfig must be owned by root"),
        ("kubeid issue", "kubeid: error: running as root without sudo: root has no personal identity"),
    ],
    ids=["config-flag", "for-non-admin", "group-escalation", "no-groups", "writable-config",
         "user-owned-issuer", "bare-root"],
)
def test_refusals_under_root(image, script, expected):
    proc = run(image, script)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert expected in proc.stderr
    assert proc.stdout == ""


# Without secure_path, sudo keeps the caller's PATH. kubeid must still only run the root-owned kubectl.
HIJACK = """
sed -i '/secure_path/d' /etc/sudoers
mkdir -p /home/alice/bin
cat > /home/alice/bin/kubectl <<'SCRIPT'
#!/bin/sh
id -u > /tmp/hijack-ran-as
exec /usr/local/bin/kubectl "$@"
SCRIPT
chmod 0755 /home/alice/bin/kubectl && chown -R alice:alice /home/alice/bin
su - alice -c 'PATH=/home/alice/bin:$PATH sudo kubeid issue'
echo "hijack-ran-as=$(cat /tmp/hijack-ran-as 2>/dev/null || echo never)"
"""


@pytest.mark.e2e
def test_caller_path_cannot_substitute_kubectl_even_without_secure_path(image):
    proc = run(image, HIJACK)
    assert "✓ kubeconfig" in proc.stdout, proc.stdout + proc.stderr
    assert "hijack-ran-as=never" in proc.stdout, proc.stdout + proc.stderr
