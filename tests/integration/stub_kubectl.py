# ABOUTME: Stand-in for kubectl in integration tests; stores CSRs as JSON files in a state dir.
# ABOUTME: `certificate approve` signs with a throwaway CA (or denies) like the real signer would.
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "support"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from testca import sign_csr  # noqa: E402


def fail(message):
    print(message, file=sys.stderr)
    return 1


def main(argv):
    state = Path(os.environ["STUB_KUBECTL_STATE"])
    with open(state / "calls.jsonl", "a") as fh:
        fh.write(json.dumps(argv) + "\n")
    if argv[:1] != ["--kubeconfig"] or len(argv) < 3:
        return fail("stub kubectl: expected --kubeconfig <path> first")
    args = argv[2:]

    if args == ["create", "-f", "-"]:
        manifest = json.load(sys.stdin)
        name = manifest["metadata"]["name"]
        (state / f"csr-{name}.json").write_text(json.dumps(manifest))
        print(f"certificatesigningrequest.certificates.k8s.io/{name} created")
        return 0

    if args[:2] == ["certificate", "approve"] and len(args) == 3:
        name = args[2]
        path = state / f"csr-{name}.json"
        obj = json.loads(path.read_text())
        if (state / "deny").exists():
            obj["status"] = {
                "conditions": [
                    {"type": "Denied", "status": "True", "reason": "StubDenied", "message": "denied by stub"}
                ]
            }
        else:
            ca_key = serialization.load_pem_private_key((state / "ca.key").read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate((state / "ca.crt").read_bytes())
            csr_pem = base64.b64decode(obj["spec"]["request"])
            cert_pem = sign_csr(csr_pem, ca_key, ca_cert, obj["spec"]["expirationSeconds"])
            obj["status"] = {
                "conditions": [{"type": "Approved", "status": "True"}],
                "certificate": base64.b64encode(cert_pem).decode("ascii"),
            }
        path.write_text(json.dumps(obj))
        print(f"certificatesigningrequest.certificates.k8s.io/{name} approved")
        return 0

    if args[:2] == ["get", "csr"] and args[3:] == ["-o", "json"]:
        path = state / f"csr-{args[2]}.json"
        if not path.exists():
            return fail(f'Error from server (NotFound): certificatesigningrequests "{args[2]}" not found')
        print(path.read_text())
        return 0

    return fail(f"stub kubectl: unsupported arguments {args}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
