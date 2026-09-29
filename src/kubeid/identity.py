# ABOUTME: Resolves who invokes kubeid and who the credential is for, via NSS (SSSD -> FreeIPA).
# ABOUTME: Maps Linux groups to Kubernetes groups through the config allowlist.
import grp
import os
import pwd
import re
from dataclasses import dataclass

# FreeIPA-style login names. No ':' or '/' so "system:" names and subject injection are impossible.
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,63}$")
K8S_GROUP_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


class IdentityError(Exception):
    pass


@dataclass(frozen=True)
class User:
    name: str
    uid: int
    gid: int
    home: str
    groups: frozenset[str]


@dataclass(frozen=True)
class Invoker:
    user: User
    via_sudo: bool


class SystemNSS:
    """User and group lookups through the host's NSS stack (SSSD on FreeIPA-enrolled hosts)."""

    def by_uid(self, uid):
        return _from_passwd(pwd.getpwuid(uid))

    def by_name(self, name):
        return _from_passwd(pwd.getpwnam(name))


def _from_passwd(entry):
    names = set()
    for gid in os.getgrouplist(entry.pw_name, entry.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue  # gid without a group entry: nothing that could be mapped
    return User(entry.pw_name, entry.pw_uid, entry.pw_gid, entry.pw_dir, frozenset(names))


def _check_username(name):
    if not USERNAME_RE.match(name):
        raise IdentityError(f"invalid username {name!r}")


_ROOT_HINT = "root has no personal identity; run `sudo kubeid ...` from your own account"


def resolve_invoker(euid, env, nss):
    """The human behind this process. Under sudo that is SUDO_UID, which sudo sets itself."""
    via_sudo = euid == 0
    if via_sudo:
        raw = env.get("SUDO_UID")
        if raw is None:
            raise IdentityError(f"running as root without sudo: {_ROOT_HINT}")
        try:
            uid = int(raw)
        except ValueError:
            raise IdentityError(f"invalid SUDO_UID {raw!r}") from None
        if uid == 0:
            raise IdentityError(f"sudo invoked by root: {_ROOT_HINT}")
    else:
        uid = euid
    try:
        user = nss.by_uid(uid)
    except KeyError:
        raise IdentityError(f"uid {uid} not found via NSS") from None
    _check_username(user.name)
    return Invoker(user, via_sudo)


def resolve_target(invoker, for_user, admin_groups, nss):
    """Who the credential is for: the invoker, or --for USER when the invoker is an admin."""
    if for_user is None:
        return invoker.user
    _check_username(for_user)
    if not admin_groups:
        raise IdentityError("--for is disabled: policy.admin_groups is empty")
    if not invoker.user.groups & admin_groups:
        raise IdentityError(f"--for requires membership in one of: {', '.join(sorted(admin_groups))}")
    try:
        target = nss.by_name(for_user)
    except KeyError:
        raise IdentityError(f"user {for_user!r} not found via NSS (is it a FreeIPA user?)") from None
    if target.uid == 0:
        raise IdentityError("refusing to issue for root")
    return target


def map_groups(user_groups, group_map, requested):
    """Kubernetes groups granted by Linux group membership, optionally narrowed by `requested`."""
    granted = {group_map[g] for g in user_groups if g in group_map}
    if not granted:
        raise IdentityError(
            "no Kubernetes groups mapped for this user; check FreeIPA group membership "
            "and the groups: section of the config"
        )
    if requested:
        missing = sorted(set(requested) - granted)
        if missing:
            raise IdentityError(f"requested groups not granted by group membership: {', '.join(missing)}")
        granted = set(requested)
    return tuple(sorted(granted))
