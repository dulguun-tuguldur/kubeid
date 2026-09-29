# ABOUTME: Unit tests for invoker/target identity resolution and group mapping.
# ABOUTME: These rules are the security boundary when kubeid runs as root via sudo.
import pytest

from kubeid.identity import (
    IdentityError,
    User,
    map_groups,
    resolve_invoker,
    resolve_target,
)

ALICE = User("alice", 1001, 1001, "/home/alice", frozenset({"alice", "k8s-loans-dev"}))
BOB = User("bob", 1002, 1002, "/home/bob", frozenset({"bob", "k8s-platform-admin", "k8s-senior-dev"}))
ROOT = User("root", 0, 0, "/root", frozenset({"root"}))
EVIL = User("Evil/O=system:masters", 1003, 1003, "/home/evil", frozenset())

GROUP_MAP = {
    "k8s-platform-admin": "platform-admin",
    "k8s-senior-dev": "cluster-viewer",
    "k8s-loans-dev": "loans-edit",
    "k8s-loans-lead": "loans-edit",
}
ADMIN_GROUPS = frozenset({"k8s-platform-admin"})


class FakeNSS:
    def __init__(self, *users):
        self.users = users

    def by_uid(self, uid):
        for user in self.users:
            if user.uid == uid:
                return user
        raise KeyError(uid)

    def by_name(self, name):
        for user in self.users:
            if user.name == name:
                return user
        raise KeyError(name)


NSS = FakeNSS(ALICE, BOB, ROOT, EVIL)


def test_non_root_invoker_is_current_user():
    invoker = resolve_invoker(1001, {}, NSS)
    assert invoker.user == ALICE
    assert invoker.via_sudo is False


def test_sudo_invoker_comes_from_sudo_uid():
    invoker = resolve_invoker(0, {"SUDO_UID": "1001", "SUDO_USER": "bob"}, NSS)
    assert invoker.user == ALICE, "SUDO_UID wins; SUDO_USER is only informational"
    assert invoker.via_sudo is True


def test_root_without_sudo_is_refused():
    with pytest.raises(IdentityError, match="root has no personal identity"):
        resolve_invoker(0, {}, NSS)


def test_sudo_from_root_is_refused():
    with pytest.raises(IdentityError, match="root has no personal identity"):
        resolve_invoker(0, {"SUDO_UID": "0"}, NSS)


def test_malformed_sudo_uid_is_refused():
    with pytest.raises(IdentityError, match="invalid SUDO_UID"):
        resolve_invoker(0, {"SUDO_UID": "abc"}, NSS)


def test_unknown_uid_is_refused():
    with pytest.raises(IdentityError, match="uid 4242 not found"):
        resolve_invoker(4242, {}, NSS)


def test_invalid_username_is_refused():
    with pytest.raises(IdentityError, match="invalid username"):
        resolve_invoker(1003, {}, NSS)


def test_target_defaults_to_invoker():
    invoker = resolve_invoker(1001, {}, NSS)
    assert resolve_target(invoker, None, ADMIN_GROUPS, NSS) == ALICE


def test_admin_can_issue_for_someone_else():
    invoker = resolve_invoker(0, {"SUDO_UID": "1002"}, NSS)
    assert resolve_target(invoker, "alice", ADMIN_GROUPS, NSS) == ALICE


def test_non_admin_cannot_issue_for_someone_else():
    invoker = resolve_invoker(0, {"SUDO_UID": "1001"}, NSS)
    with pytest.raises(IdentityError, match="--for requires membership in one of: k8s-platform-admin"):
        resolve_target(invoker, "bob", ADMIN_GROUPS, NSS)


def test_for_with_no_admin_groups_configured_is_refused():
    invoker = resolve_invoker(1002, {}, NSS)
    with pytest.raises(IdentityError, match="policy.admin_groups is empty"):
        resolve_target(invoker, "alice", frozenset(), NSS)


def test_for_unknown_user_is_refused():
    invoker = resolve_invoker(1002, {}, NSS)
    with pytest.raises(IdentityError, match="user 'carol' not found"):
        resolve_target(invoker, "carol", ADMIN_GROUPS, NSS)


def test_for_root_is_refused():
    invoker = resolve_invoker(1002, {}, NSS)
    with pytest.raises(IdentityError, match="refusing to issue for root"):
        resolve_target(invoker, "root", ADMIN_GROUPS, NSS)


def test_for_invalid_username_is_refused_before_lookup():
    invoker = resolve_invoker(1002, {}, NSS)
    with pytest.raises(IdentityError, match="invalid username"):
        resolve_target(invoker, "system:admin", ADMIN_GROUPS, NSS)


def test_map_groups_maps_sorts_and_ignores_unmapped():
    assert map_groups(BOB.groups, GROUP_MAP, None) == ("cluster-viewer", "platform-admin")


def test_map_groups_deduplicates_many_to_one():
    groups = frozenset({"k8s-loans-dev", "k8s-loans-lead"})
    assert map_groups(groups, GROUP_MAP, None) == ("loans-edit",)


def test_map_groups_narrowing_to_subset():
    assert map_groups(BOB.groups, GROUP_MAP, ["cluster-viewer"]) == ("cluster-viewer",)


def test_map_groups_refuses_ungranted_group():
    with pytest.raises(IdentityError, match="not granted by group membership: platform-admin"):
        map_groups(ALICE.groups, GROUP_MAP, ["platform-admin"])


def test_map_groups_refuses_user_without_mapped_groups():
    with pytest.raises(IdentityError, match="no Kubernetes groups mapped"):
        map_groups(frozenset({"alice", "wheel"}), GROUP_MAP, None)
