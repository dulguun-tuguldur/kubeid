# ABOUTME: Writes kubeconfigs (they contain private keys) as 0600 files, atomically.
# ABOUTME: When running as root, the write happens in a child process running as the invoker.
import os
import subprocess
import sys
import tempfile


class OutputError(Exception):
    pass


def write_private_file(path, data, as_user, run=subprocess.run, grouplist=os.getgrouplist):
    """Write data to path. as_user=None writes directly; otherwise drop to that user first.

    Dropping privileges means symlink or path tricks can only reach files the
    invoker could already write themselves.
    """
    if as_user is None:
        _write_atomic(path, data)
        return
    # -I and cwd="/" keep files in the invoker's working directory off the child's import path.
    proc = run(
        [sys.executable, "-I", "-m", "kubeid.output", path],
        input=data,
        capture_output=True,
        cwd="/",
        user=as_user.uid,
        group=as_user.gid,
        extra_groups=grouplist(as_user.name, as_user.gid),
        umask=0o077,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip()
        raise OutputError(f"writing {path} as {as_user.name} failed: {detail}")


def _write_atomic(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".kubeid-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # rename replaces a symlink at `path` itself; it never writes through it
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _main():
    try:
        _write_atomic(sys.argv[1], sys.stdin.buffer.read())
    except OSError as err:
        print(f"{err.strerror}: {err.filename!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
