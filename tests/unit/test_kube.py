# ABOUTME: Unit tests for the kubectl adapter that creates, approves and polls CSRs.
# ABOUTME: Uses a fake subprocess runner so exact kubectl arguments are asserted.
import base64
import json
import subprocess
from datetime import datetime, timezone

import pytest

from kubeid.kube import KubeError, Kubectl, csr_manifest, csr_name


class FakeRun:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, args, input=None, capture_output=None, text=None, timeout=None):
        self.calls.append({"args": args, "input": input})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        returncode, stdout, stderr = response
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def csr_json(certificate=None, conditions=None):
    status = {}
    if certificate is not None:
        status["certificate"] = base64.b64encode(certificate).decode()
    if conditions is not None:
        status["conditions"] = conditions
    return json.dumps({"kind": "CertificateSigningRequest", "status": status})


def kubectl(run, clock=None):
    clock = clock or FakeClock()
    return Kubectl("/etc/kubeid/issuer.kubeconfig", run=run, sleep=clock.sleep, monotonic=clock.monotonic)


def test_csr_manifest_shape():
    manifest = csr_manifest("kubeid-alice-x", b"CSR PEM", 43200, requested_by="bob", issued_for="alice")
    assert manifest["apiVersion"] == "certificates.k8s.io/v1"
    assert manifest["kind"] == "CertificateSigningRequest"
    assert manifest["metadata"]["name"] == "kubeid-alice-x"
    assert manifest["metadata"]["labels"] == {"app.kubernetes.io/managed-by": "kubeid"}
    assert manifest["metadata"]["annotations"] == {
        "kubeid/requested-by": "bob",
        "kubeid/issued-for": "alice",
    }
    spec = manifest["spec"]
    assert base64.b64decode(spec["request"]) == b"CSR PEM"
    assert spec["signerName"] == "kubernetes.io/kube-apiserver-client"
    assert spec["expirationSeconds"] == 43200
    assert spec["usages"] == ["digital signature", "client auth"]


def test_csr_name_is_dns_safe_and_timestamped():
    when = datetime(2026, 9, 29, 10, 15, 0, tzinfo=timezone.utc)
    assert csr_name("j.doe_x", when, "ab12") == "kubeid-j-doe-x-20260929t101500-ab12"


def test_create_csr_pipes_manifest_json_to_kubectl():
    run = FakeRun((0, "created", ""))
    manifest = csr_manifest("kubeid-alice-x", b"CSR", 600, requested_by="alice", issued_for="alice")
    kubectl(run).create_csr(manifest)
    (call,) = run.calls
    assert call["args"] == ["kubectl", "--kubeconfig", "/etc/kubeid/issuer.kubeconfig", "create", "-f", "-"]
    assert json.loads(call["input"]) == manifest


def test_approve_csr_calls_certificate_approve():
    run = FakeRun((0, "approved", ""))
    kubectl(run).approve_csr("kubeid-alice-x")
    assert run.calls[0]["args"][-3:] == ["certificate", "approve", "kubeid-alice-x"]


def test_kubectl_failure_raises_with_stderr():
    run = FakeRun((1, "", 'Error from server (Forbidden): certificatesigningrequests is forbidden'))
    with pytest.raises(KubeError, match="Forbidden"):
        kubectl(run).approve_csr("kubeid-alice-x")


def test_missing_kubectl_binary_raises():
    run = FakeRun(FileNotFoundError("kubectl"))
    with pytest.raises(KubeError, match="kubectl not found"):
        kubectl(run).approve_csr("kubeid-alice-x")


def test_wait_for_certificate_polls_until_issued():
    clock = FakeClock()
    run = FakeRun((0, csr_json(conditions=[{"type": "Approved"}]), ""), (0, csr_json(b"CERT PEM"), ""))
    cert = kubectl(run, clock).wait_for_certificate("kubeid-alice-x", timeout=30, interval=0.5)
    assert cert == b"CERT PEM"
    assert clock.sleeps == [0.5]
    assert run.calls[0]["args"][-5:] == ["get", "csr", "kubeid-alice-x", "-o", "json"]


def test_wait_for_certificate_raises_on_denied():
    denied = [{"type": "Denied", "status": "True", "reason": "PolicyDenied", "message": "not today"}]
    run = FakeRun((0, csr_json(conditions=denied), ""))
    with pytest.raises(KubeError, match="Denied: PolicyDenied: not today"):
        kubectl(run).wait_for_certificate("kubeid-alice-x")


def test_wait_for_certificate_times_out():
    clock = FakeClock()
    run = FakeRun(*[(0, csr_json(), "")] * 10)
    with pytest.raises(KubeError, match="not issued within 2s"):
        kubectl(run, clock).wait_for_certificate("kubeid-alice-x", timeout=2, interval=0.5)
