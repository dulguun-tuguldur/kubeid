# ABOUTME: Unit tests for the CLI's root-only safety checks (config path and file trust).
# ABOUTME: Simulates euid 0 and fake stat results; no real root needed.
from types import SimpleNamespace

import pytest

from kubeid import cli
from kubeid.config import ConfigError

TRUSTED = SimpleNamespace(st_uid=0, st_mode=0o100644)


@pytest.fixture
def root_env(tmp_path, monkeypatch):
    """A config on disk plus a fake os.stat that reports every path as root-owned unless overridden."""
    ca = tmp_path / "ca.crt"
    issuer = tmp_path / "issuer.kubeconfig"
    config = tmp_path / "config.yaml"
    config.write_text(
        "cluster: {name: prod, server: 'https://k8s:6443', ca_file: '%s'}\n"
        "issuer: {kubeconfig: '%s'}\n"
        "groups: {k8s-platform-admin: platform-admin}\n" % (ca, issuer)
    )
    overrides = {}

    def fake_stat(path):
        return overrides.get(str(path), TRUSTED)

    monkeypatch.setattr(cli, "DEFAULT_CONFIG", str(config))
    monkeypatch.setattr(cli.os, "stat", fake_stat)
    monkeypatch.setattr(cli.os.path, "realpath", lambda p: str(p))
    return SimpleNamespace(config=str(config), issuer=str(issuer), ca=str(ca), dir=str(tmp_path), overrides=overrides)


def args(config=None):
    return SimpleNamespace(config=config)


def test_non_root_may_choose_config(root_env):
    loaded = cli._load_config(args(root_env.config), euid=1001)
    assert loaded.cluster_name == "prod"


def test_root_refuses_caller_supplied_config(root_env):
    with pytest.raises(ConfigError, match="--config is not allowed when running as root"):
        cli._load_config(args("/home/alice/evil.yaml"), euid=0)


def test_root_loads_default_config_when_everything_is_trusted(root_env):
    assert cli._load_config(args(), euid=0).issuer_kubeconfig == root_env.issuer


def test_root_refuses_config_not_owned_by_root(root_env):
    root_env.overrides[root_env.config] = SimpleNamespace(st_uid=1001, st_mode=0o100644)
    with pytest.raises(ConfigError, match="must be owned by root"):
        cli._load_config(args(), euid=0)


def test_root_refuses_config_in_writable_directory(root_env):
    root_env.overrides[root_env.dir] = SimpleNamespace(st_uid=0, st_mode=0o041777)
    with pytest.raises(ConfigError, match="group/world-writable"):
        cli._load_config(args(), euid=0)


def test_root_refuses_group_writable_issuer_kubeconfig(root_env):
    # a writable issuer kubeconfig could gain an exec credential plugin that kubectl runs as root
    root_env.overrides[root_env.issuer] = SimpleNamespace(st_uid=0, st_mode=0o100660)
    with pytest.raises(ConfigError, match="issuer.kubeconfig is group/world-writable"):
        cli._load_config(args(), euid=0)


def test_root_refuses_user_owned_ca_file(root_env):
    root_env.overrides[root_env.ca] = SimpleNamespace(st_uid=1001, st_mode=0o100644)
    with pytest.raises(ConfigError, match="ca.crt must be owned by root"):
        cli._load_config(args(), euid=0)


def test_parse_groups_splits_and_ignores_blanks():
    assert cli._parse_groups(" a, b ,,") == ("a", "b")
    assert cli._parse_groups("") is None
    assert cli._parse_groups(None) is None
