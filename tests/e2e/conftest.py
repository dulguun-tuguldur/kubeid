# ABOUTME: End-to-end harness: boots K3s in Docker, applies `kubeid rbac`, and builds the issuer kubeconfig.
# ABOUTME: Helpers are plain functions so scripts can drive the harness too.
import base64
import grp
import os
import pwd
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

K3S_IMAGE_ENV = "KUBEID_E2E_K3S_IMAGE"
ADMIN_TARGET_USER = "daemon"
TARGET_NAMESPACE = "e2e-ns"


@dataclass
class K3s:
    """A K3s API server running in Docker and reachable from the host."""

    server: str
    admin_kubeconfig: Path
    ca_file: Path


@dataclass
class KubeidCluster:
    """A K3s cluster prepared for kubeid: RBAC applied and the issuer kubeconfig written."""

    k3s: K3s
    config_file: Path
    daemon_skip_reason: str | None


def run(cmd, timeout=60, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)


def describe(result):
    return (
        f"command: {' '.join(str(arg) for arg in result.args)}\n"
        f"exit code: {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def run_checked(cmd, what, timeout=60, **kwargs):
    result = run(cmd, timeout=timeout, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{what} failed\n{describe(result)}")
    return result


def wait_for_command(what, cmd, ready, timeout):
    """Re-run cmd every second until ready(result) is true; raise with the last output on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        result = run(cmd, timeout=30)
        if ready(result):
            return result
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out after {timeout}s waiting for {what}\nlast attempt:\n{describe(result)}"
            )
        time.sleep(1)


def kubectl_cmd(kubeconfig, *args):
    return ["kubectl", "--kubeconfig", str(kubeconfig), *args]


def kubeid_cmd(*args):
    return [sys.executable, "-m", "kubeid", *args]


def local_k3s_images(docker_images_output):
    return [line for line in docker_images_output.split() if not line.endswith(":<none>")]


def pick_k3s_image(timeout=180):
    """$KUBEID_E2E_K3S_IMAGE, else the first local rancher/k3s image, waiting for a pull in progress."""
    image = os.environ.get(K3S_IMAGE_ENV)
    if image:
        return image
    run_checked(["docker", "info", "--format", "{{.ServerVersion}}"], "contacting Docker (is it running?)")
    result = wait_for_command(
        f"a local rancher/k3s image (docker pull one, or set {K3S_IMAGE_ENV})",
        ["docker", "images", "rancher/k3s", "--format", "{{.Repository}}:{{.Tag}}"],
        ready=lambda r: local_k3s_images(r.stdout),
        timeout=timeout,
    )
    return local_k3s_images(result.stdout)[0]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_k3s_kubeconfig(container):
    result = wait_for_command(
        "K3s to write /etc/rancher/k3s/k3s.yaml",
        ["docker", "exec", container, "cat", "/etc/rancher/k3s/k3s.yaml"],
        # client-key-data is the last field K3s writes, so its presence means the file is complete.
        ready=lambda r: r.returncode == 0 and "client-key-data" in r.stdout,
        timeout=120,
    )
    return yaml.safe_load(result.stdout)


def boot_k3s(container, workdir):
    """Start K3s in a new container named `container` and wait until it can sign CSRs."""
    image = pick_k3s_image()
    port = free_port()
    server = f"https://127.0.0.1:{port}"
    run_checked(
        [
            "docker", "run", "-d", "--privileged", "--name", container,
            "-p", f"127.0.0.1:{port}:6443", image,
            "server", "--disable=traefik", "--disable=servicelb", "--disable=metrics-server",
            "--tls-san=127.0.0.1",
        ],
        f"starting a K3s container from {image}",
        timeout=300,
    )
    try:
        kubeconfig = read_k3s_kubeconfig(container)
        cluster = kubeconfig["clusters"][0]["cluster"]
        cluster["server"] = server
        admin_kubeconfig = workdir / "admin.kubeconfig"
        admin_kubeconfig.write_text(yaml.safe_dump(kubeconfig))
        ca_file = workdir / "ca.crt"
        ca_file.write_bytes(base64.b64decode(cluster["certificate-authority-data"]))
        wait_for_command(
            "the API server to report /readyz ok",
            kubectl_cmd(admin_kubeconfig, "--request-timeout=5s", "get", "--raw", "/readyz"),
            ready=lambda r: r.stdout.strip() == "ok",
            timeout=120,
        )
        # The controller-manager creates the default ServiceAccount; it is also what signs CSRs.
        wait_for_command(
            "the controller-manager to create the default ServiceAccount",
            kubectl_cmd(admin_kubeconfig, "get", "serviceaccount", "default", "-n", "default"),
            ready=lambda r: r.returncode == 0,
            timeout=120,
        )
    except RuntimeError as error:
        logs = run(["docker", "logs", "--tail", "40", container])
        raise RuntimeError(f"{error}\nlast K3s container logs:\n{logs.stdout}{logs.stderr}") from None
    return K3s(server=server, admin_kubeconfig=admin_kubeconfig, ca_file=ca_file)


def remove_container(container):
    # -v also removes the anonymous volumes the rancher/k3s image declares for cluster state.
    run_checked(["docker", "rm", "-f", "-v", container], f"removing container {container}", timeout=120)


def group_names(user, gid):
    """Names of the NSS groups `user` belongs to; gids without a group entry are skipped."""
    names = set()
    for group_id in os.getgrouplist(user, gid):
        try:
            names.add(grp.getgrgid(group_id).gr_name)
        except KeyError:
            continue
    return names


def admin_target_group(invoker):
    """(daemon's primary group, None), or (None, why daemon can't be a distinct admin-mode target)."""
    try:
        target = pwd.getpwnam(ADMIN_TARGET_USER)
    except KeyError:
        return None, f"admin-mode test needs a local {ADMIN_TARGET_USER!r} user; none exists here"
    target_group = grp.getgrgid(target.pw_gid).gr_name
    invoker_group = grp.getgrgid(invoker.pw_gid).gr_name
    if target_group in group_names(invoker.pw_name, invoker.pw_gid):
        return None, (
            f"invoker {invoker.pw_name!r} is a member of {target_group!r}, the primary group of "
            f"{ADMIN_TARGET_USER!r}, so the two identities would share Kubernetes groups"
        )
    if invoker_group in group_names(target.pw_name, target.pw_gid):
        return None, (
            f"{ADMIN_TARGET_USER!r} is a member of {invoker_group!r}, the invoker's primary group, "
            f"so the two identities would share Kubernetes groups"
        )
    return target_group, None


def kubeid_config(k3s, issuer_kubeconfig, invoker_group, daemon_group):
    groups = {invoker_group: "e2e-viewers"}
    rbac = [{"group": "e2e-viewers", "clusterrole": "view"}]
    if daemon_group is not None:
        groups[daemon_group] = "e2e-daemons"
        rbac.append({"group": "e2e-daemons", "clusterrole": "edit", "namespaces": [TARGET_NAMESPACE]})
    return {
        "cluster": {"name": "e2e", "server": k3s.server, "ca_file": str(k3s.ca_file)},
        "issuer": {"kubeconfig": str(issuer_kubeconfig)},
        "policy": {"default_ttl": "1h", "max_ttl": "24h", "admin_groups": [invoker_group]},
        "groups": groups,
        "rbac": rbac,
    }


def apply_kubeid_rbac(k3s, config_file, workdir):
    manifests = run_checked(kubeid_cmd("rbac", "--config", str(config_file)), "kubeid rbac", cwd=workdir)
    run_checked(
        kubectl_cmd(k3s.admin_kubeconfig, "apply", "-f", "-"),
        "applying the kubeid rbac output",
        input=manifests.stdout,
    )


def write_issuer_kubeconfig(k3s, path):
    """Build a kubeconfig for the kubeid-issuer ServiceAccount from its token Secret."""
    result = wait_for_command(
        "the kubeid-issuer-token Secret to be populated with a token",
        kubectl_cmd(
            k3s.admin_kubeconfig,
            "get", "secret", "kubeid-issuer-token", "-n", "kubeid", "-o", "jsonpath={.data.token}",
        ),
        ready=lambda r: r.returncode == 0 and r.stdout.strip() != "",
        timeout=60,
    )
    token = base64.b64decode(result.stdout).decode()
    run_checked(
        kubectl_cmd(
            path, "config", "set-cluster", "e2e", f"--server={k3s.server}",
            f"--certificate-authority={k3s.ca_file}", "--embed-certs=true",
        ),
        "writing the issuer kubeconfig cluster",
    )
    run_checked(
        kubectl_cmd(path, "config", "set-credentials", "kubeid-issuer", f"--token={token}"),
        "writing the issuer kubeconfig credentials",
    )
    run_checked(
        kubectl_cmd(path, "config", "set-context", "e2e", "--cluster=e2e", "--user=kubeid-issuer"),
        "writing the issuer kubeconfig context",
    )
    run_checked(kubectl_cmd(path, "config", "use-context", "e2e"), "selecting the issuer kubeconfig context")


@pytest.fixture(scope="module")
def kubeid_cluster(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("kubeid-e2e")
    invoker = pwd.getpwuid(os.getuid())
    invoker_group = grp.getgrgid(invoker.pw_gid).gr_name
    daemon_group, daemon_skip_reason = admin_target_group(invoker)
    container = f"kubeid-e2e-{secrets.token_hex(4)}"
    with pytest.MonkeyPatch.context() as env:
        # Keep kubectl's discovery cache (ours and kubeid's own kubectl calls) out of ~/.kube.
        env.setenv("KUBECACHEDIR", str(workdir / "kube-cache"))
        try:
            k3s = boot_k3s(container, workdir)
            run_checked(
                kubectl_cmd(k3s.admin_kubeconfig, "create", "namespace", TARGET_NAMESPACE),
                f"creating namespace {TARGET_NAMESPACE}",
            )
            # `kubeid rbac` only reads the config, so the issuer kubeconfig it names need not exist yet.
            issuer_kubeconfig = workdir / "issuer.kubeconfig"
            config_file = workdir / "kubeid.yaml"
            config = kubeid_config(k3s, issuer_kubeconfig, invoker_group, daemon_group)
            config_file.write_text(yaml.safe_dump(config, sort_keys=False))
            apply_kubeid_rbac(k3s, config_file, workdir)
            write_issuer_kubeconfig(k3s, issuer_kubeconfig)
            yield KubeidCluster(k3s=k3s, config_file=config_file, daemon_skip_reason=daemon_skip_reason)
        finally:
            remove_container(container)
