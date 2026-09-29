# ABOUTME: Unit tests for the issue orchestration with every dependency faked.
# ABOUTME: Verifies ordering, annotations, default paths, and fail-before-side-effects rules.
import base64
from datetime import datetime, timezone

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID

from kubeid.certs import CertError
from kubeid.config import parse_config
from kubeid.identity import IdentityError, Invoker, User
from kubeid.issue import IssueOptions, issue
from testca import cert_to_pem, make_ca, sign_csr

NOW = datetime(2026, 9, 29, 10, 15, 0, tzinfo=timezone.utc)
ALICE = User("alice", 1001, 1001, "/home/alice", frozenset({"alice", "k8s-loans-dev"}))
BOB = User("bob", 1002, 1002, "/home/bob", frozenset({"bob", "k8s-platform-admin"}))

CONFIG = parse_config(
    {
        "cluster": {"name": "prod", "server": "https://k8s:6443", "ca_file": "/etc/kubeid/ca.crt"},
        "issuer": {"kubeconfig": "/etc/kubeid/issuer.kubeconfig"},
        "policy": {"default_ttl": "12h", "max_ttl": "24h", "admin_groups": ["k8s-platform-admin"]},
        "groups": {"k8s-platform-admin": "platform-admin", "k8s-loans-dev": "loans-edit"},
    }
)


class FakeNSS:
    def by_name(self, name):
        return {"alice": ALICE, "bob": BOB}[name]


class FakeKube:
    """Plays the API server + signer; optionally tampers with the subject."""

    def __init__(self, tamper_subject=None):
        self.ca_key, self.ca_cert = make_ca()
        self.tamper_subject = tamper_subject
        self.calls = []
        self.manifests = {}

    def create_csr(self, manifest):
        self.calls.append("create")
        self.manifests[manifest["metadata"]["name"]] = manifest

    def approve_csr(self, name):
        self.calls.append("approve")

    def wait_for_certificate(self, name):
        self.calls.append("wait")
        spec = self.manifests[name]["spec"]
        csr_pem = base64.b64decode(spec["request"])
        return sign_csr(csr_pem, self.ca_key, self.ca_cert, spec["expirationSeconds"], subject=self.tamper_subject)


class Recorder:
    def __init__(self):
        self.writes = []
        self.audits = []

    def write(self, path, data):
        self.writes.append((path, data))

    def audit(self, message):
        self.audits.append(message)


def run_issue(invoker, options, kube=None, read_file=None, rec=None):
    kube = kube or FakeKube()
    rec = rec or Recorder()
    ca_pem = cert_to_pem(kube.ca_cert)
    result = issue(
        options,
        CONFIG,
        invoker,
        FakeNSS(),
        kube,
        now=NOW,
        suffix="ab12",
        read_file=read_file or (lambda path: ca_pem),
        write_file=rec.write,
        audit=rec.audit,
        cwd="/work",
    )
    return result, kube, rec


def test_self_issue_writes_kubeconfig_into_own_home():
    result, kube, rec = run_issue(Invoker(ALICE, via_sudo=True), IssueOptions())
    assert kube.calls == ["create", "approve", "wait"]
    assert result.path == "/home/alice/.kube/kubeid/prod.yaml"
    assert result.groups == ("loans-edit",)
    assert result.ttl_seconds == 43200
    assert result.csr_name == "kubeid-alice-20260929t101500-ab12"

    (path, data), = rec.writes
    assert path == "/home/alice/.kube/kubeid/prod.yaml"
    doc = yaml.safe_load(data)
    cert = x509.load_pem_x509_certificate(base64.b64decode(doc["users"][0]["user"]["client-certificate-data"]))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "alice"


def test_self_issue_annotates_and_sets_expiration():
    _, kube, _ = run_issue(Invoker(ALICE, via_sudo=True), IssueOptions(ttl="2h"))
    (manifest,) = kube.manifests.values()
    assert manifest["metadata"]["annotations"] == {"kubeid/requested-by": "alice", "kubeid/issued-for": "alice"}
    assert manifest["spec"]["expirationSeconds"] == 7200


def test_audit_line_records_who_for_whom_and_what():
    _, _, rec = run_issue(Invoker(BOB, via_sudo=True), IssueOptions(for_user="alice"))
    (line,) = rec.audits
    assert "user=alice" in line
    assert "groups=loans-edit" in line
    assert "requested_by=bob" in line
    assert "csr=kubeid-alice-20260929t101500-ab12" in line


def test_admin_issue_defaults_to_file_in_invokers_cwd():
    result, kube, rec = run_issue(Invoker(BOB, via_sudo=True), IssueOptions(for_user="alice"))
    assert result.path == "/work/kubeid-prod-alice.yaml"
    (manifest,) = kube.manifests.values()
    assert manifest["metadata"]["annotations"] == {"kubeid/requested-by": "bob", "kubeid/issued-for": "alice"}


def test_explicit_out_path_is_made_absolute():
    result, _, rec = run_issue(Invoker(ALICE, via_sudo=False), IssueOptions(out="creds/prod.yaml"))
    assert result.path == "/work/creds/prod.yaml"
    assert rec.writes[0][0] == "/work/creds/prod.yaml"


def test_identity_failure_happens_before_any_cluster_call():
    kube = FakeKube()
    with pytest.raises(IdentityError):
        run_issue(Invoker(ALICE, via_sudo=True), IssueOptions(for_user="bob"), kube=kube)
    assert kube.calls == []


def test_unreadable_ca_file_fails_before_any_cluster_call():
    kube = FakeKube()

    def broken(path):
        raise OSError(f"cannot read {path}")

    with pytest.raises(OSError, match="/etc/kubeid/ca.crt"):
        run_issue(Invoker(ALICE, via_sudo=True), IssueOptions(), kube=kube, read_file=broken)
    assert kube.calls == []


def test_tampered_certificate_is_never_written():
    evil = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "system:masters"),
        ]
    )
    kube = FakeKube(tamper_subject=evil)
    rec = Recorder()
    with pytest.raises(CertError, match="groups"):
        run_issue(Invoker(ALICE, via_sudo=True), IssueOptions(), kube=kube, rec=rec)
    assert rec.writes == []
    assert rec.audits == []
