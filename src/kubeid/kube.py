# ABOUTME: Thin kubectl adapter for the CSR lifecycle: create, approve, wait for the certificate.
# ABOUTME: Shells out to kubectl so auth and contexts behave exactly as they do for humans.
import base64
import json
import re
import subprocess
import time

SIGNER_NAME = "kubernetes.io/kube-apiserver-client"
_NAME_UNSAFE = re.compile(r"[^a-z0-9-]+")


class KubeError(Exception):
    pass


def csr_name(username, now, suffix):
    safe = _NAME_UNSAFE.sub("-", username.lower()).strip("-")
    return f"kubeid-{safe}-{now.strftime('%Y%m%dt%H%M%S')}-{suffix}"


def csr_manifest(name, csr_pem, ttl_seconds, requested_by, issued_for):
    return {
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {
            "name": name,
            "labels": {"app.kubernetes.io/managed-by": "kubeid"},
            "annotations": {"kubeid/requested-by": requested_by, "kubeid/issued-for": issued_for},
        },
        "spec": {
            "request": base64.b64encode(csr_pem).decode("ascii"),
            "signerName": SIGNER_NAME,
            "expirationSeconds": ttl_seconds,
            "usages": ["digital signature", "client auth"],
        },
    }


class Kubectl:
    def __init__(
        self,
        kubeconfig,
        run=subprocess.run,
        kubectl="kubectl",
        sleep=time.sleep,
        monotonic=time.monotonic,
        timeout=60,
    ):
        self.kubeconfig = kubeconfig
        self.run = run
        self.kubectl = kubectl
        self.sleep = sleep
        self.monotonic = monotonic
        self.timeout = timeout

    def _run(self, *args, stdin=None):
        cmd = [self.kubectl, "--kubeconfig", self.kubeconfig, *args]
        try:
            proc = self.run(cmd, input=stdin, capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError:
            raise KubeError(f"kubectl not found (looked for {self.kubectl!r} on PATH)") from None
        except subprocess.TimeoutExpired:
            raise KubeError(f"kubectl {' '.join(args)} timed out after {self.timeout}s") from None
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip()
            raise KubeError(f"kubectl {' '.join(args)} failed: {detail}")
        return proc.stdout

    def create_csr(self, manifest):
        self._run("create", "-f", "-", stdin=json.dumps(manifest))

    def approve_csr(self, name):
        self._run("certificate", "approve", name)

    def get_csr(self, name):
        return json.loads(self._run("get", "csr", name, "-o", "json"))

    def wait_for_certificate(self, name, timeout=30.0, interval=0.5):
        start = self.monotonic()
        while True:
            status = self.get_csr(name).get("status", {})
            for condition in status.get("conditions", []):
                if condition.get("type") in ("Denied", "Failed"):
                    raise KubeError(
                        f"CSR {name} {condition['type']}: "
                        f"{condition.get('reason', '')}: {condition.get('message', '')}"
                    )
            certificate = status.get("certificate")
            if certificate:
                return base64.b64decode(certificate)
            if self.monotonic() - start >= timeout:
                raise KubeError(
                    f"CSR {name} not issued within {timeout:g}s; is kube-controller-manager "
                    f"signing {SIGNER_NAME}?"
                )
            self.sleep(interval)
