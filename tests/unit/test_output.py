# ABOUTME: Unit tests for the private kubeconfig writer.
# ABOUTME: Files must be 0600, replaced atomically, and never written through symlinks.
import os
import stat
import subprocess
import sys

import pytest

from kubeid.identity import User
from kubeid.output import OutputError, write_private_file


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_creates_parent_dirs_0700_and_file_0600(tmp_path):
    target = tmp_path / "home" / ".kube" / "kubeid" / "prod.yaml"
    write_private_file(str(target), b"kubeconfig", None)
    assert target.read_bytes() == b"kubeconfig"
    assert mode(target) == 0o600
    assert mode(target.parent) == 0o700


def test_replaces_existing_file_and_tightens_mode(tmp_path):
    target = tmp_path / "prod.yaml"
    target.write_bytes(b"old")
    os.chmod(target, 0o644)
    write_private_file(str(target), b"new", None)
    assert target.read_bytes() == b"new"
    assert mode(target) == 0o600


def test_replaces_symlink_instead_of_following_it(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    target = tmp_path / "prod.yaml"
    target.symlink_to(victim)
    write_private_file(str(target), b"kubeconfig", None)
    assert victim.read_bytes() == b"precious"
    assert not target.is_symlink()
    assert target.read_bytes() == b"kubeconfig"


def test_leaves_no_temp_files_behind(tmp_path):
    write_private_file(str(tmp_path / "prod.yaml"), b"kubeconfig", None)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["prod.yaml"]


def test_as_user_runs_writer_subprocess_with_dropped_privileges():
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    alice = User("alice", 1001, 1001, "/home/alice", frozenset({"alice"}))
    write_private_file("/home/alice/.kube/kubeid/prod.yaml", b"kubeconfig", alice,
                       run=fake_run, grouplist=lambda name, gid: [1001, 2000])
    (args, kwargs) = calls[0]
    assert args == [sys.executable, "-m", "kubeid.output", "/home/alice/.kube/kubeid/prod.yaml"]
    assert kwargs["input"] == b"kubeconfig"
    assert kwargs["user"] == 1001
    assert kwargs["group"] == 1001
    assert kwargs["extra_groups"] == [1001, 2000]
    assert kwargs["umask"] == 0o077


def test_as_user_failure_raises_with_child_stderr():
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, b"", b"Permission denied: '/etc/x'")

    alice = User("alice", 1001, 1001, "/home/alice", frozenset({"alice"}))
    with pytest.raises(OutputError, match="Permission denied"):
        write_private_file("/etc/x", b"kubeconfig", alice, run=fake_run, grouplist=lambda n, g: [1001])
