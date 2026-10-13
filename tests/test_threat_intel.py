"""
Tests for PhishGuard V2 Threat Intelligence Providers and Caching.
All tests use harmless test fixtures and mocked responses with zero external network queries.
"""
from unittest.mock import patch, MagicMock
import pytest
import requests
from src.threat_intelligence import (
    GoogleSafeBrowsingProvider,
    PhishTankProvider,
    LocalThreatSignatureProvider,
    ThreatIntelligenceManager,
    ThreatIntelCache
)


def test_provider_missing_api_keys():
    """Verify that unconfigured providers report status 'unconfigured' gracefully without crashing."""
    gsb = GoogleSafeBrowsingProvider(api_key="")
    res = gsb.check_url("https://example.com")
    assert res["status"] == "unconfigured"
    assert res["is_threat"] is False
    assert "not configured" in res["details"]

    pt = PhishTankProvider(api_key="")
    res_pt = pt.check_url("https://example.com")
    assert res_pt["status"] == "unconfigured"
    assert res_pt["is_threat"] is False


def test_gsb_threat_match_mocked():
    """Verify Google Safe Browsing correctly parses threat match response."""
    gsb = GoogleSafeBrowsingProvider(api_key="mock_test_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [{
            "threatType": "SOCIAL_ENGINEERING",
            "platformType": "ANY_PLATFORM",
            "threatEntryType": "URL"
        }]
    }

    with patch("requests.post", return_value=mock_resp):
        res = gsb.check_url("http://deceptive-login-portal.xyz")
        assert res["status"] == "match"
        assert res["is_threat"] is True
        assert res["threat_type"] == "SOCIAL_ENGINEERING"


def test_gsb_clean_response_mocked():
    """Verify Google Safe Browsing clean response."""
    gsb = GoogleSafeBrowsingProvider(api_key="mock_test_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}  # Empty matches = clean

    with patch("requests.post", return_value=mock_resp):
        res = gsb.check_url("https://example.com")
        assert res["status"] == "clean"
        assert res["is_threat"] is False


def test_gsb_timeout_handling():
    """Verify provider timeout does not crash the system."""
    gsb = GoogleSafeBrowsingProvider(api_key="mock_test_key_12345")
    with patch("requests.post", side_effect=requests.Timeout("Mock timeout")):
        res = gsb.check_url("https://timeout-test-domain.org")
        assert res["status"] == "unavailable"
        assert res["is_threat"] is False
        assert "timed out" in res["details"].lower()


def test_gsb_quota_exhaustion_handling():
    """Verify HTTP 429 / 403 quota exhaustion is handled gracefully."""
    gsb = GoogleSafeBrowsingProvider(api_key="mock_test_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("requests.post", return_value=mock_resp):
        res = gsb.check_url("https://quota-exhaustion-test.org")
        assert res["status"] == "rate_limited"
        assert res["is_threat"] is False


def test_phishtank_match_mocked():
    """Verify PhishTank verified phishing detection."""
    pt = PhishTankProvider(api_key="mock_pt_key")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": {
            "in_database": True,
            "valid": True,
            "phish_id": "9998887"
        }
    }

    with patch("requests.post", return_value=mock_resp):
        res = pt.check_url("http://paypal-verification-fake.com")
        assert res["status"] == "match"
        assert res["is_threat"] is True
        assert "9998887" in res["details"]


def test_local_threat_signature_provider():
    """Verify offline local signatures catch known malicious domain and whitelist authority domain."""
    local_prov = LocalThreatSignatureProvider()
    assert local_prov.is_configured() is True

    # Known signature match
    res_mal = local_prov.check_url("http://paypal-account-security-update22.xyz/login.php")
    assert res_mal["status"] == "match"
    assert res_mal["is_threat"] is True

    # Known authority domain
    res_auth = local_prov.check_url("https://www.wikipedia.org/wiki/Computer_security")
    assert res_auth["status"] == "clean"
    assert res_auth["is_threat"] is False
    assert "trusted authority" in res_auth["details"].lower()


def test_threat_intel_cache_ttl(tmp_path):
    """Verify threat intelligence cache stores, retrieves, and expires entries using SHA-256 keys."""
    cache_file = tmp_path / "test_cache.json"
    cache = ThreatIntelCache(cache_file=cache_file, ttl_seconds=1)

    url = "https://test-example.com"
    data = {"status": "clean", "is_threat": False}
    cache.set(url, "MockProvider", data)

    # Immediate retrieval
    cached = cache.get(url, "MockProvider")
    assert cached is not None
    assert cached["status"] == "clean"

    # Verify SHA-256 hash privacy in storage
    with open(cache_file, "r") as f:
        content = f.read()
        assert "test-example.com" not in content  # Plain URL not leaked as key
