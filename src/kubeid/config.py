# ABOUTME: Loads and validates /etc/kubeid/config.yaml into an immutable Config.
# ABOUTME: Unknown keys and unsafe values are errors so typos never silently weaken policy.
import re
import stat
from dataclasses import dataclass

import yaml

from kubeid.identity import K8S_GROUP_RE
from kubeid.ttl import TTLError, resolve_ttl

DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RbacRule:
    group: str
    clusterrole: str
    namespaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    cluster_name: str
    server: str
    ca_file: str
    issuer_kubeconfig: str
    default_ttl: str
    max_ttl: str
    admin_groups: frozenset[str]
    group_map: dict[str, str]
    rbac: tuple[RbacRule, ...]


def _reject_unknown(section, allowed, where):
    for key in section:
        if key not in allowed:
            raise ConfigError(f"unknown key {key!r} in {where}")


def _mapping(data, key, allowed, required=True):
    section = data.get(key)
    if section is None and not required:
        return {}
    if not isinstance(section, dict):
        raise ConfigError(f"{key} section is required and must be a mapping")
    _reject_unknown(section, allowed, key)
    return section


def _required_str(section, where, key):
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} is required")
    return value


def _rbac_rule(entry, k8s_groups):
    if not isinstance(entry, dict):
        raise ConfigError("each rbac entry must be a mapping")
    _reject_unknown(entry, {"group", "clusterrole", "namespaces"}, "rbac entry")
    group = _required_str(entry, "rbac", "group")
    if group not in k8s_groups:
        raise ConfigError(f"rbac group {group!r} is not a value in groups")
    clusterrole = _required_str(entry, "rbac", "clusterrole")
    namespaces = entry.get("namespaces", [])
    if not isinstance(namespaces, list):
        raise ConfigError(f"rbac namespaces for {group!r} must be a list")
    for namespace in namespaces:
        if not isinstance(namespace, str) or not DNS_LABEL_RE.match(namespace):
            raise ConfigError(f"invalid namespace {namespace!r} in rbac entry for {group!r}")
    return RbacRule(group, clusterrole, tuple(namespaces))


def parse_config(data):
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping")
    _reject_unknown(data, {"cluster", "issuer", "policy", "groups", "rbac"}, "config")
    cluster = _mapping(data, "cluster", {"name", "server", "ca_file"})
    issuer = _mapping(data, "issuer", {"kubeconfig"})
    policy = _mapping(data, "policy", {"default_ttl", "max_ttl", "admin_groups"}, required=False)

    name = _required_str(cluster, "cluster", "name")
    if not DNS_LABEL_RE.match(name):
        raise ConfigError(f"cluster.name {name!r} must be a DNS label")
    server = _required_str(cluster, "cluster", "server")
    if not server.startswith("https://"):
        raise ConfigError(f"cluster.server must start with https:// (got {server!r})")

    default_ttl = str(policy.get("default_ttl", "12h"))
    max_ttl = str(policy.get("max_ttl", "24h"))
    try:
        resolve_ttl(None, default_ttl, max_ttl)
    except TTLError as err:
        raise ConfigError(f"policy.default_ttl/max_ttl: {err}") from err

    admin_groups = policy.get("admin_groups", [])
    if not isinstance(admin_groups, list) or not all(isinstance(g, str) and g for g in admin_groups):
        raise ConfigError("policy.admin_groups must be a list of group names")

    groups = data.get("groups")
    if not isinstance(groups, dict) or not groups:
        raise ConfigError("groups must map at least one Linux group to a Kubernetes group")
    group_map = {}
    for linux_group, k8s_group in groups.items():
        if not isinstance(linux_group, str) or not linux_group:
            raise ConfigError(f"invalid Linux group {linux_group!r} in groups")
        if not isinstance(k8s_group, str) or not K8S_GROUP_RE.match(k8s_group):
            raise ConfigError(f"invalid Kubernetes group {k8s_group!r} for {linux_group!r} in groups")
        group_map[linux_group] = k8s_group

    rbac_entries = data.get("rbac") or []
    if not isinstance(rbac_entries, list):
        raise ConfigError("rbac must be a list")
    rbac = tuple(_rbac_rule(entry, set(group_map.values())) for entry in rbac_entries)

    return Config(
        cluster_name=name,
        server=server,
        ca_file=_required_str(cluster, "cluster", "ca_file"),
        issuer_kubeconfig=_required_str(issuer, "issuer", "kubeconfig"),
        default_ttl=default_ttl,
        max_ttl=max_ttl,
        admin_groups=frozenset(admin_groups),
        group_map=group_map,
        rbac=rbac,
    )


def load_config(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as err:
        raise ConfigError(f"cannot read config {path}: {err.strerror}") from err
    except yaml.YAMLError as err:
        raise ConfigError(f"invalid YAML in {path}: {err}") from err
    return parse_config(data)


def check_trusted_file(path, st):
    """When kubeid runs as root, anything it reads must be controlled by root only."""
    if st.st_uid != 0:
        raise ConfigError(f"{path} must be owned by root when kubeid runs as root")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{path} is group/world-writable; fix with: chmod go-w {path}")
