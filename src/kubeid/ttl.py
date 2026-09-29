# ABOUTME: Parses credential lifetimes like "30m", "12h", "1d" and enforces policy bounds.
# ABOUTME: Kubernetes rejects CSR expirationSeconds below 600, so that is the floor.
import re

MIN_TTL_SECONDS = 600
_UNITS = {"m": 60, "h": 3600, "d": 86400}
_PATTERN = re.compile(r"^([0-9]+)([mhd])$")


class TTLError(ValueError):
    pass


def parse_duration(text):
    match = _PATTERN.match(text.strip()) if isinstance(text, str) else None
    if not match:
        raise TTLError(f"invalid duration {text!r}: use <number>m, <number>h or <number>d")
    seconds = int(match.group(1)) * _UNITS[match.group(2)]
    if seconds <= 0:
        raise TTLError(f"invalid duration {text!r}: must be positive")
    return seconds


def resolve_ttl(requested, default, maximum):
    """Return the lifetime in seconds for a request, or raise if outside policy."""
    text = requested if requested is not None else default
    seconds = parse_duration(text)
    if seconds < MIN_TTL_SECONDS:
        raise TTLError(f"ttl {text} too short: must be at least {format_duration(MIN_TTL_SECONDS)}")
    if seconds > parse_duration(maximum):
        raise TTLError(f"ttl {text} exceeds policy max_ttl {maximum}")
    return seconds


def format_duration(seconds):
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"
