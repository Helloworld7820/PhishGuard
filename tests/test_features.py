"""
Unit tests for URL feature extraction and heuristic indicator detection.
All tests execute strictly offline with zero external network access.
"""
import pytest
import config
from src.feature_extraction import (
    extract_features,
    extract_features_vector,
    is_valid_ip,
    count_subdomains,
    identify_suspicious_indicators
)


def test_empty_and_none_input():
    """Verify that empty, None, and whitespace inputs return zero-vectors without throwing errors."""
    for empty_val in ["", "   ", None]:
        feats = extract_features(empty_val)
        assert isinstance(feats, dict)
        assert len(feats) == len(config.FEATURE_NAMES)
        assert all(v == 0 for v in feats.values())

        vec = extract_features_vector(empty_val)
        assert len(vec) == len(config.FEATURE_NAMES)
        assert all(v == 0.0 for v in vec)


def test_missing_scheme():
    """Verify URLs without http:// or https:// are parsed without crashing."""
    url = "example.com/login/auth"
    feats = extract_features(url)
    assert feats["domain_length"] > 0
    assert feats["is_https"] == 0
    assert feats["suspicious_keyword_count"] >= 1


def test_https_detection():
    """Verify HTTPS scheme detection."""
    https_url = "https://secure.example.com"
    http_url = "http://example.com"
    assert extract_features(https_url)["is_https"] == 1
    assert extract_features(http_url)["is_https"] == 0


def test_ip_address_detection():
    """Verify IPv4 and IPv6 detection in hostname."""
    assert is_valid_ip("192.168.1.1") == 1
    assert is_valid_ip("10.0.0.1") == 1
    assert is_valid_ip("example.com") == 0
    assert is_valid_ip("not-an-ip") == 0

    ipv4_url = "http://192.168.1.1/login.php"
    feats = extract_features(ipv4_url)
    assert feats["has_ip_address"] == 1

    indicators = identify_suspicious_indicators(ipv4_url, feats)
    assert any(i["title"] == "IP Address as Hostname" for i in indicators)


def test_at_symbol_detection():
    """Verify presence of @ symbol is captured and flagged."""
    at_url = "http://legit-site.com@attacker-controlled.net/auth"
    feats = extract_features(at_url)
    assert feats["has_at_symbol"] == 1

    indicators = identify_suspicious_indicators(at_url, feats)
    assert any(i["title"] == "URL Contains '@' Symbol" for i in indicators)


def test_subdomain_counting():
    """Verify subdomain parsing logic with standard and multipart TLDs."""
    assert count_subdomains("example.com") == 0
    assert count_subdomains("sub.example.com") == 1
    assert count_subdomains("a.b.example.com") == 2
    assert count_subdomains("portal.service.co.uk") == 1
    assert count_subdomains("192.168.1.1") == 0


def test_url_shortener_detection():
    """Verify detection of popular URL shortening services."""
    short_url = "http://bit.ly/update-token-99"
    feats = extract_features(short_url)
    assert feats["is_shortened"] == 1

    indicators = identify_suspicious_indicators(short_url, feats)
    assert any(i["title"] == "URL Shortener Detected" for i in indicators)


def test_suspicious_ports():
    """Verify detection of non-standard port numbers."""
    port_url = "http://bank-portal.com:8080/login"
    feats = extract_features(port_url)
    assert feats["has_suspicious_port"] == 1

    normal_port_url = "https://bank-portal.com:443/login"
    assert extract_features(normal_port_url)["has_suspicious_port"] == 0


def test_percent_encoding():
    """Verify percent-encoded characters detection."""
    encoded_url = "http://example.com/%73%65%63%75%72%65"
    assert extract_features(encoded_url)["has_percent_encoding"] == 1


def test_malformed_urls():
    """Verify that severely malformed or Unicode URLs do not throw unhandled exceptions."""
    weird_urls = [
        "http://",
        "://invalid-url",
        "http://user:pass@host:99999/path",
        "https://тест.рф/login",
        "http://[:::1]/test",
        "////invalid/////",
        "http://example.com?query=1&b=2&c=3"
    ]
    for url in weird_urls:
        feats = extract_features(url)
        assert isinstance(feats, dict)
        vec = extract_features_vector(url)
        assert len(vec) == len(config.FEATURE_NAMES)


def test_feature_vector_order_consistency():
    """Verify that extract_features_vector strictly matches config.FEATURE_NAMES order."""
    url = "https://test.com/login"
    feats = extract_features(url)
    vec = extract_features_vector(url)
    for i, name in enumerate(config.FEATURE_NAMES):
        assert float(feats[name]) == vec[i]
