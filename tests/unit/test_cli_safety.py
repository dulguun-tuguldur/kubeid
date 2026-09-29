# ABOUTME: Unit tests for the CLI's root-only safety checks (config path and file trust).
# ABOUTME: Simulates euid 0 and fake stat results; no real root needed.
import os
import pwd
from types import SimpleNamespace

import pytest

from kubeid import cli
from kubeid.config import ConfigError

TRUSTED = SimpleNamespace(st_uid=0, st_mode=0o100644)


@pytest.fixture
def root_env(tmp_path, monkeypatch):
    """A config on disk plus a fake stat (cli's seam, not global os.stat) reporting paths as root-owned."""
    ca = tmp_path / "ca.crt"
    issuer = tmp_path / "issuer.kubeconfig"
    config = tmp_path / "config.yaml"
    config.write_text(
        "cluster: {name: prod, server: 'https://k8s:6443', ca_file: '%s'}\n"
        "issuer: {kubeconfig: '%s'}\n"
        "groups: {k8s-platform-admin: platform-admin}\n" % (ca, issuer)
    )
    # the issuer kubeconfig holds a CA-grade token, so its trusted baseline is 0600
    overrides = {str(issuer): SimpleNamespace(st_uid=0, st_mode=0o100600)}

    def fake_stat(path):
        return overrides.get(str(path), TRUSTED)

    monkeypatch.setattr(cli, "DEFAULT_CONFIG", str(config))
    monkeypatch.setattr(cli, "_stat", fake_stat)
    monkeypatch.setattr(cli, "_realpath", lambda p: str(p))
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


def test_root_refuses_writable_ancestor_directory(root_env):
    root_env.overrides[os.path.dirname(root_env.dir)] = SimpleNamespace(st_uid=0, st_mode=0o040777)
    with pytest.raises(ConfigError, match="group/world-writable"):
        cli._load_config(args(), euid=0)


def test_root_refuses_readable_issuer_kubeconfig(root_env):
    root_env.overrides[root_env.issuer] = SimpleNamespace(st_uid=0, st_mode=0o100644)
    with pytest.raises(ConfigError, match="issuer.kubeconfig must not be readable by group/others"):
        cli._load_config(args(), euid=0)


def test_non_root_uses_kubectl_from_path_with_inherited_env():
    assert cli._kubectl_for(1001) == ("kubectl", None)


def test_root_resolves_kubectl_from_safe_path_only(root_env, monkeypatch):
    searched = []

    def fake_which(name, path=None):
        searched.append((name, path))
        return "/usr/local/bin/kubectl"

    monkeypatch.setattr(cli.shutil, "which", fake_which)
    binary, env = cli._kubectl_for(0)
    assert searched == [("kubectl", cli.SAFE_PATH)]
    assert binary == "/usr/local/bin/kubectl"
    assert env == {"PATH": cli.SAFE_PATH, "HOME": pwd.getpwuid(0).pw_dir}


def test_root_refuses_missing_kubectl(root_env, monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name, path=None: None)
    with pytest.raises(ConfigError, match="kubectl not found in /usr/local/sbin"):
        cli._kubectl_for(0)


def test_root_refuses_user_owned_kubectl(root_env, monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name, path=None: "/usr/local/bin/kubectl")
    root_env.overrides["/usr/local/bin/kubectl"] = SimpleNamespace(st_uid=1001, st_mode=0o100755)
    with pytest.raises(ConfigError, match="/usr/local/bin/kubectl must be owned by root"):
        cli._kubectl_for(0)


def test_refusals_are_audited(tmp_path, monkeypatch, capsys):
    lines = []
    monkeypatch.setattr(cli, "_audit", lines.append)
    config = tmp_path / "config.yaml"
    config.write_text("polcy: {}\n")
    assert cli.main(["issue", "--config", str(config)]) == 1
    assert capsys.readouterr().err == "kubeid: error: unknown key 'polcy' in config\n"
    (line,) = lines
    assert line.startswith(f"refused uid={os.geteuid()} args=issue --config ")
    assert line.endswith("error=unknown key 'polcy' in config")


def test_audit_escapes_control_characters(monkeypatch):
    sent = []
    monkeypatch.setattr(cli.syslog, "openlog", lambda *a, **k: None)
    monkeypatch.setattr(cli.syslog, "closelog", lambda: None)
    monkeypatch.setattr(cli.syslog, "syslog", lambda priority, message: sent.append(message))
    cli._audit("refused args=--groups 'x\nkubeid: issued user=root'")
    assert sent == ["refused args=--groups 'x\\x0akubeid: issued user=root'"]
