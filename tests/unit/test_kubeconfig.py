# ABOUTME: Unit tests for the kubeconfig document kubeid writes for engineers.
# ABOUTME: Checks structure, context naming and embedded base64 credentials.
import base64

import yaml

from kubeid.kubeconfig import build_kubeconfig


def test_build_kubeconfig_embeds_credentials_and_sets_context():
    text = build_kubeconfig(
        cluster_name="prod",
        server="https://10.10.0.10:6443",
        ca_pem=b"CA PEM",
        username="alice",
        cert_pem=b"CERT PEM",
        key_pem=b"KEY PEM",
    )
    doc = yaml.safe_load(text)
    assert doc["apiVersion"] == "v1"
    assert doc["kind"] == "Config"
    assert doc["current-context"] == "alice@prod"

    (cluster,) = doc["clusters"]
    assert cluster["name"] == "prod"
    assert cluster["cluster"]["server"] == "https://10.10.0.10:6443"
    assert base64.b64decode(cluster["cluster"]["certificate-authority-data"]) == b"CA PEM"

    (user,) = doc["users"]
    assert user["name"] == "alice@prod"
    assert base64.b64decode(user["user"]["client-certificate-data"]) == b"CERT PEM"
    assert base64.b64decode(user["user"]["client-key-data"]) == b"KEY PEM"

    (context,) = doc["contexts"]
    assert context == {"name": "alice@prod", "context": {"cluster": "prod", "user": "alice@prod"}}
