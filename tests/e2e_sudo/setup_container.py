# ABOUTME: Runs at image build time: creates the stub signer CA and a root-owned /etc/kubeid.
# ABOUTME: Mirrors the production layout from README (config 0644, issuer kubeconfig 0600).
import os
import sys
from pathlib import Path

sys.path.insert(0, "/src/tests/support")
from testca import cert_to_pem, key_to_pem, make_ca  # noqa: E402

state = Path("/var/lib/stub-kubectl")
state.mkdir(mode=0o700, parents=True, exist_ok=True)
ca_key, ca_cert = make_ca()
(state / "ca.key").write_bytes(key_to_pem(ca_key))
(state / "ca.crt").write_bytes(cert_to_pem(ca_cert))

etc = Path("/etc/kubeid")
etc.mkdir(mode=0o755, exist_ok=True)
(etc / "ca.crt").write_bytes(cert_to_pem(ca_cert))
os.chmod(etc / "ca.crt", 0o644)
(etc / "issuer.kubeconfig").write_text("# stub kubectl ignores this file\n")
os.chmod(etc / "issuer.kubeconfig", 0o600)
(etc / "config.yaml").write_text(
    "cluster: {name: e2e, server: 'https://stub.invalid:6443', ca_file: /etc/kubeid/ca.crt}\n"
    "issuer: {kubeconfig: /etc/kubeid/issuer.kubeconfig}\n"
    "policy: {default_ttl: 1h, max_ttl: 24h, admin_groups: [k8s-platform-admin]}\n"
    "groups: {k8s-loans-dev: loans-edit, k8s-platform-admin: platform-admin}\n"
)
os.chmod(etc / "config.yaml", 0o644)
