# ABOUTME: Unit tests for kubeid config parsing, validation and file trust checks.
# ABOUTME: Invalid config must fail loudly; typos must never be silently ignored.
import copy
from types import SimpleNamespace

import pytest

from kubeid.config import (
    ConfigError,
    RbacRule,
    check_private_file,
    check_trusted_file,
    load_config,
    parse_config,
)

VALID = {
    "cluster": {
        "name": "prod",
        "server": "https://10.10.0.10:6443",
        "ca_file": "/etc/kubeid/prod-ca.crt",
    },
    "issuer": {"kubeconfig": "/etc/kubeid/issuer.kubeconfig"},
    "policy": {"default_ttl": "8h", "max_ttl": "24h", "admin_groups": ["k8s-platform-admin"]},
    "groups": {
        "k8s-platform-admin": "platform-admin",
        "k8s-senior-dev": "cluster-viewer",
        "k8s-loans-dev": "loans-edit",
    },
    "rbac": [
        {"group": "platform-admin", "clusterrole": "cluster-admin"},
        {"group": "loans-edit", "clusterrole": "edit", "namespaces": ["loans-dev", "loans-stg"]},
    ],
}


def valid():
    return copy.deepcopy(VALID)


def test_parse_config_reads_all_sections():
    cfg = parse_config(valid())
    assert cfg.cluster_name == "prod"
    assert cfg.server == "https://10.10.0.10:6443"
    assert cfg.ca_file == "/etc/kubeid/prod-ca.crt"
    assert cfg.issuer_kubeconfig == "/etc/kubeid/issuer.kubeconfig"
    assert cfg.default_ttl == "8h"
    assert cfg.max_ttl == "24h"
    assert cfg.admin_groups == frozenset({"k8s-platform-admin"})
    assert cfg.group_map["k8s-loans-dev"] == "loans-edit"
    assert cfg.rbac == (
        RbacRule(group="platform-admin", clusterrole="cluster-admin", namespaces=()),
        RbacRule(group="loans-edit", clusterrole="edit", namespaces=("loans-dev", "loans-stg")),
    )


def test_policy_defaults_apply_when_section_missing():
    data = valid()
    del data["policy"]
    cfg = parse_config(data)
    assert cfg.default_ttl == "12h"
    assert cfg.max_ttl == "24h"
    assert cfg.admin_groups == frozenset()


def test_rbac_section_is_optional():
    data = valid()
    del data["rbac"]
    assert parse_config(data).rbac == ()


def test_rejects_unknown_top_level_key():
    data = valid()
    data["polcy"] = {}
    with pytest.raises(ConfigError, match="unknown key 'polcy'"):
        parse_config(data)


def test_rejects_unknown_nested_key():
    data = valid()
    data["policy"]["max_tll"] = "48h"
    with pytest.raises(ConfigError, match="unknown key 'max_tll' in policy"):
        parse_config(data)


def test_rejects_missing_cluster_server():
    data = valid()
    del data["cluster"]["server"]
    with pytest.raises(ConfigError, match="cluster.server is required"):
        parse_config(data)


def test_rejects_plain_http_server():
    data = valid()
    data["cluster"]["server"] = "http://10.10.0.10:6443"
    with pytest.raises(ConfigError, match="must start with https://"):
        parse_config(data)


def test_rejects_empty_group_map():
    data = valid()
    data["groups"] = {}
    with pytest.raises(ConfigError, match="groups must map at least one"):
        parse_config(data)


def test_rejects_system_group_mapping():
    data = valid()
    data["groups"]["k8s-platform-admin"] = "system:masters"
    with pytest.raises(ConfigError, match="invalid Kubernetes group 'system:masters'"):
        parse_config(data)


def test_rejects_rbac_for_unmapped_group():
    data = valid()
    data["rbac"].append({"group": "ghost", "clusterrole": "view"})
    with pytest.raises(ConfigError, match="rbac group 'ghost' is not a value in groups"):
        parse_config(data)


def test_rejects_invalid_namespace():
    data = valid()
    data["rbac"][1]["namespaces"] = ["Loans_Dev"]
    with pytest.raises(ConfigError, match="invalid namespace 'Loans_Dev'"):
        parse_config(data)


def test_rejects_default_ttl_above_max():
    data = valid()
    data["policy"]["default_ttl"] = "48h"
    with pytest.raises(ConfigError, match="policy.default_ttl"):
        parse_config(data)


def test_load_config_reads_yaml_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "cluster:\n"
        "  name: prod\n"
        "  server: https://10.10.0.10:6443\n"
        "  ca_file: /etc/kubeid/prod-ca.crt\n"
        "issuer:\n"
        "  kubeconfig: /etc/kubeid/issuer.kubeconfig\n"
        "groups:\n"
        "  k8s-platform-admin: platform-admin\n"
    )
    cfg = load_config(str(path))
    assert cfg.group_map == {"k8s-platform-admin": "platform-admin"}


def test_load_config_rejects_non_mapping_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(ConfigError, match="must be a YAML mapping"):
        load_config(str(path))


def test_load_config_reports_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(str(tmp_path / "nope.yaml"))


def test_check_trusted_file_accepts_root_owned_0600():
    check_trusted_file("/etc/kubeid/config.yaml", SimpleNamespace(st_uid=0, st_mode=0o100600))


def test_check_trusted_file_rejects_non_root_owner():
    with pytest.raises(ConfigError, match="must be owned by root"):
        check_trusted_file("/etc/kubeid/config.yaml", SimpleNamespace(st_uid=1001, st_mode=0o100600))


def test_check_trusted_file_rejects_group_or_world_writable():
    with pytest.raises(ConfigError, match="group/world-writable"):
        check_trusted_file("/etc/kubeid/config.yaml", SimpleNamespace(st_uid=0, st_mode=0o100664))


def test_check_private_file_accepts_0600():
    check_private_file("/etc/kubeid/issuer.kubeconfig", SimpleNamespace(st_uid=0, st_mode=0o100600))


def test_check_private_file_rejects_group_or_world_readable():
    with pytest.raises(ConfigError, match="must not be readable by group/others"):
        check_private_file("/etc/kubeid/issuer.kubeconfig", SimpleNamespace(st_uid=0, st_mode=0o100640))
