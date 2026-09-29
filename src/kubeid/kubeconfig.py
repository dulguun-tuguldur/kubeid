# ABOUTME: Builds the kubeconfig YAML handed to an engineer: one cluster, one user, one context.
# ABOUTME: Credentials are embedded as base64 so the file is self-contained.
import base64

import yaml


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def build_kubeconfig(cluster_name, server, ca_pem, username, cert_pem, key_pem):
    identity = f"{username}@{cluster_name}"
    doc = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {"name": cluster_name, "cluster": {"server": server, "certificate-authority-data": _b64(ca_pem)}}
        ],
        "users": [
            {
                "name": identity,
                "user": {"client-certificate-data": _b64(cert_pem), "client-key-data": _b64(key_pem)},
            }
        ],
        "contexts": [{"name": identity, "context": {"cluster": cluster_name, "user": identity}}],
        "current-context": identity,
    }
    return yaml.safe_dump(doc, sort_keys=False)
