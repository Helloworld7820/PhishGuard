"""
Unit tests for input validation and sanitization.
Ensures safety constraints against injection, malformed payloads, and buffer overruns.
"""
import pytest
from app import validate_url_input


def test_valid_urls():
    """Verify standard legitimate and suspicious URLs pass validation."""
    valid_samples = [
        "https://google.com",
        "http://example.org/path/to/resource?arg=1",
        "https://sub.domain.co.uk",
        "example.com",
        "http://192.168.1.1/admin"
    ]
    for url in valid_samples:
        is_valid, cleaned = validate_url_input(url)
        assert is_valid is True
        assert cleaned == url.strip()


def test_empty_or_whitespace_urls():
    """Verify empty or purely whitespace inputs fail gracefully."""
    invalid_samples = ["", "   ", "\t", None]
    for url in invalid_samples:
        is_valid, msg = validate_url_input(url)
        assert is_valid is False
        assert "valid" in msg.lower() or "blank" in msg.lower()


def test_overly_long_url():
    """Verify URLs exceeding 2048 characters are rejected."""
    long_url = "https://example.com/" + "a" * 2100
    is_valid, msg = validate_url_input(long_url)
    assert is_valid is False
    assert "maximum" in msg.lower()


def test_control_characters():
    """Verify URLs containing unprintable control characters are rejected."""
    bad_url = "https://example.com/bad\x00path"
    is_valid, msg = validate_url_input(bad_url)
    assert is_valid is False
    assert "control" in msg.lower()
