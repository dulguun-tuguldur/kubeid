# ABOUTME: Unit tests for TTL parsing and policy bounds.
# ABOUTME: Covers accepted formats, rejected input, and min/max enforcement.
import pytest

from kubeid.ttl import TTLError, format_duration, parse_duration, resolve_ttl


@pytest.mark.parametrize(
    "text,seconds",
    [("10m", 600), ("90m", 5400), ("12h", 43200), ("1d", 86400), (" 2h ", 7200)],
)
def test_parse_duration_accepts_minutes_hours_days(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "12", "h", "1.5h", "-1h", "12x", "1h30m", "0h"])
def test_parse_duration_rejects_bad_input(text):
    with pytest.raises(TTLError):
        parse_duration(text)


def test_resolve_ttl_uses_default_when_not_requested():
    assert resolve_ttl(None, "12h", "24h") == 43200


def test_resolve_ttl_accepts_requested_within_bounds():
    assert resolve_ttl("1h", "12h", "24h") == 3600


def test_resolve_ttl_rejects_above_max():
    with pytest.raises(TTLError, match="exceeds policy max_ttl 24h"):
        resolve_ttl("48h", "12h", "24h")


def test_resolve_ttl_rejects_below_kubernetes_minimum():
    with pytest.raises(TTLError, match="at least 10m"):
        resolve_ttl("5m", "12h", "24h")


def test_format_duration_prefers_hours_then_minutes():
    assert format_duration(43200) == "12h"
    assert format_duration(5400) == "90m"
    assert format_duration(600) == "10m"
