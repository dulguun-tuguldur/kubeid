# ABOUTME: Unit tests for RBAC manifest rendering from kubeid config.
# ABOUTME: Issuer permissions must stay minimal; group bindings must follow config exactly.
import yaml

from kubeid.config import parse_config
from kubeid.rbac import render_manifests, render_yaml

CONFIG = parse_config(
    {
        "cluster": {"name": "prod", "server": "https://k8s:6443", "ca_file": "/ca.crt"},
        "issuer": {"kubeconfig": "/issuer"},
        "groups": {"k8s-platform-admin": "platform-admin", "k8s-loans-dev": "loans-edit"},
        "rbac": [
            {"group": "platform-admin", "clusterrole": "cluster-admin"},
            {"group": "loans-edit", "clusterrole": "edit", "namespaces": ["loans-dev", "loans-stg"]},
        ],
    }
)


def find(docs, kind, name, namespace=None):
    for doc in docs:
        meta = doc["metadata"]
        if doc["kind"] == kind and meta["name"] == name and meta.get("namespace") == namespace:
            return doc
    raise AssertionError(f"{kind} {namespace}/{name} not rendered")


def test_issuer_objects_are_rendered():
    docs = render_manifests(CONFIG)
    find(docs, "Namespace", "kubeid")
    find(docs, "ServiceAccount", "kubeid-issuer", "kubeid")
    secret = find(docs, "Secret", "kubeid-issuer-token", "kubeid")
    assert secret["type"] == "kubernetes.io/service-account-token"
    assert secret["metadata"]["annotations"] == {"kubernetes.io/service-account.name": "kubeid-issuer"}


def test_issuer_clusterrole_is_minimal():
    role = find(render_manifests(CONFIG), "ClusterRole", "kubeid:issuer")
    assert role["rules"] == [
        {
            "apiGroups": ["certificates.k8s.io"],
            "resources": ["certificatesigningrequests"],
            "verbs": ["create", "get"],
        },
        {
            "apiGroups": ["certificates.k8s.io"],
            "resources": ["certificatesigningrequests/approval"],
            "verbs": ["update"],
        },
        {
            "apiGroups": ["certificates.k8s.io"],
            "resources": ["signers"],
            "resourceNames": ["kubernetes.io/kube-apiserver-client"],
            "verbs": ["approve"],
        },
    ]


def test_issuer_binding_targets_service_account():
    binding = find(render_manifests(CONFIG), "ClusterRoleBinding", "kubeid:issuer")
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": "kubeid:issuer",
    }
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "kubeid-issuer", "namespace": "kubeid"}]


def test_cluster_wide_rule_becomes_clusterrolebinding():
    binding = find(render_manifests(CONFIG), "ClusterRoleBinding", "kubeid:platform-admin:cluster-admin")
    assert binding["roleRef"]["name"] == "cluster-admin"
    assert binding["subjects"] == [
        {"kind": "Group", "name": "platform-admin", "apiGroup": "rbac.authorization.k8s.io"}
    ]


def test_namespaced_rule_becomes_rolebinding_per_namespace():
    docs = render_manifests(CONFIG)
    for namespace in ("loans-dev", "loans-stg"):
        binding = find(docs, "RoleBinding", "kubeid:loans-edit:edit", namespace)
        assert binding["roleRef"] == {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "edit",
        }
        assert binding["subjects"][0]["name"] == "loans-edit"


def test_every_object_is_labeled_managed_by_kubeid():
    for doc in render_manifests(CONFIG):
        assert doc["metadata"]["labels"] == {"app.kubernetes.io/managed-by": "kubeid"}


def test_render_yaml_is_valid_multi_document_yaml():
    docs = [d for d in yaml.safe_load_all(render_yaml(CONFIG)) if d]
    assert docs == render_manifests(CONFIG)
