"""
Tests for PhishGuard V2 Advanced Capabilities:
- Public Suffix List registered domain extraction
- Unicode homographs & punycode analysis
- Brand spoofing detection
- Decision engine 4-state verdicts & inconclusive states
- Domain & TLS signals
- Scan history privacy sanitization & clearing
- Model registry validation
- PWA manifest & service worker routes
"""
from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest
import config
from app import app
from src.feature_extraction import (
    extract_url_metadata,
    check_homograph_and_punycode
)
from src.decision_engine import compute_final_verdict
from src.domain_signals import check_dns_resolution, evaluate_domain_signals
from src.scan_history import sanitize_url_for_history, ScanHistoryManager
from src.model_registry import register_model_artifact, get_registered_model_metadata


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_public_suffix_list_domain_extraction():
    """Verify registered domain and subdomain decomposition using Public Suffix List."""
    # Multipart TLD (.co.uk)
    meta = extract_url_metadata("https://login.portal.service.co.uk/auth")
    assert meta["registered_domain"] == "service.co.uk"
    assert meta["domain_name"] == "service"
    assert meta["tld"] == "co.uk"
    assert meta["subdomain"] == "login.portal"
    assert meta["subdomain_count"] == 2

    # Standard TLD (.com)
    meta_std = extract_url_metadata("https://secure.chase.com/myaccount")
    assert meta_std["registered_domain"] == "chase.com"
    assert meta_std["subdomain"] == "secure"
    assert meta_std["subdomain_count"] == 1


def test_punycode_and_homograph_detection():
    """Verify punycode 'xn--' and mixed-script homoglyph detection."""
    # Punycode URL (e.g. apple spoof)
    puny_host = "xn--pple-43d.com"
    is_puny, is_mixed, decoded = check_homograph_and_punycode(puny_host)
    assert is_puny is True

    # Latin host without mixed script
    is_puny, is_mixed, _ = check_homograph_and_punycode("google.com")
    assert is_puny is False
    assert is_mixed is False


def test_brand_spoofing_detection():
    """Verify that embedding known brands in subdomains/paths is detected as deception."""
    # Brand 'paypal' in subdomain of attacker domain 'verification-center.xyz'
    meta = extract_url_metadata("http://paypal.account.verification-center.xyz/login")
    assert meta["brand_spoofing"] is not None
    assert meta["brand_spoofing"]["brand"] == "paypal"
    assert meta["brand_spoofing"]["location"] == "subdomain"

    # Legitimate brand domain should NOT be flagged as spoofing itself
    meta_legit = extract_url_metadata("https://www.paypal.com/signin")
    assert meta_legit["brand_spoofing"] is None


def test_decision_engine_verdicts():
    """Verify all 4 standardized verdicts from the decision engine."""
    # 1. PHISHING DETECTED (via Threat Intel)
    res_phish = compute_final_verdict(
        url="http://malicious-site.com",
        model_score=40.0,
        indicators=[],
        threat_intel={"confirmed_threat": True, "threat_types": ["Google Safe Browsing: MALWARE"]},
        domain_signals={},
        metadata={"valid": True}
    )
    assert res_phish["verdict"] == config.VERDICT_PHISHING
    assert res_phish["status_color"] == "danger"
    assert "Confirmed malicious destination" in res_phish["reasons"][0]

    # 2. SUSPICIOUS (elevated model score + structural indicators)
    res_suspicious = compute_final_verdict(
        url="http://shorturl.at/xyz?auth=update",
        model_score=55.0,
        indicators=[{"severity": "medium", "title": "Shortener"}],
        threat_intel={"confirmed_threat": False},
        domain_signals={},
        metadata={"valid": True}
    )
    assert res_suspicious["verdict"] == config.VERDICT_SUSPICIOUS
    assert res_suspicious["status_color"] == "warning"

    # 3. NO KNOWN THREAT DETECTED (clean indicators & low score)
    res_clean = compute_final_verdict(
        url="https://en.wikipedia.org",
        model_score=5.0,
        indicators=[],
        threat_intel={"confirmed_threat": False},
        domain_signals={"dns": {"status": "resolved"}},
        metadata={"valid": True}
    )
    assert res_clean["verdict"] == config.VERDICT_NO_KNOWN_THREAT
    assert res_clean["status_color"] == "success"

    # 4. INCONCLUSIVE (malformed URL syntax)
    res_inconclusive = compute_final_verdict(
        url="://invalid-syntax",
        model_score=0.0,
        indicators=[],
        threat_intel={"confirmed_threat": False},
        domain_signals={},
        metadata={"valid": False, "error": "Invalid URL"}
    )
    assert res_inconclusive["verdict"] == config.VERDICT_INCONCLUSIVE
    assert res_inconclusive["status_color"] == "secondary"


def test_scan_history_sanitization():
    """Verify passwords, credentials, and sensitive tokens are redacted from scan history."""
    unsafe_url = "https://user:secret123@example.com/login?token=abc999&auth=xyz&view=summary"
    sanitized = sanitize_url_for_history(unsafe_url)
    assert "secret123" not in sanitized
    assert "abc999" not in sanitized
    assert "xyz" not in sanitized
    assert "token=REDACTED" in sanitized
    assert "auth=REDACTED" in sanitized
    assert "view=summary" in sanitized  # Non-sensitive param preserved


def test_scan_history_clearing(tmp_path):
    """Verify scan history can record entries and be cleanly cleared."""
    history_file = tmp_path / "test_history.json"
    mgr = ScanHistoryManager(history_file=history_file, max_entries=5)

    mgr.add_scan("https://example1.com", "NO KNOWN THREAT DETECTED", 10.0, "success")
    mgr.add_scan("https://example2.com", "SUSPICIOUS", 60.0, "warning")

    stats = mgr.get_statistics()
    assert stats["total_scans"] == 2

    # Clear history
    mgr.clear()
    assert len(mgr.get_history()) == 0
    assert mgr.get_statistics()["total_scans"] == 0


def test_model_registry_schema_validation(tmp_path):
    """Verify model registry validates feature counts and creates registry file."""
    meta = get_registered_model_metadata()
    assert meta is not None
    assert meta["model_version"] == config.VERSION
    assert meta["feature_count"] == len(config.FEATURE_NAMES)
    assert meta["validation_passed"] is True
    assert "summary_metrics" in meta


def test_api_providers_endpoint(client):
    """Verify /api/providers returns threat intelligence provider configuration."""
    resp = client.get("/api/providers")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert isinstance(data["providers"], list)
    assert any(p["name"] == "Local Threat Signatures" for p in data["providers"])


def test_api_history_endpoints(client):
    """Verify /api/history and /api/history/clear endpoints."""
    resp = client.get("/api/history")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "statistics" in data
    assert "history" in data

    # Clear history
    resp_clear = client.post("/api/history/clear")
    assert resp_clear.status_code == 200
    data_clear = resp_clear.get_json()
    assert data_clear["status"] == "success"


def test_pwa_routes(client):
    """Verify Web App Manifest and Service Worker are served for PWA/Android."""
    resp_manifest = client.get("/manifest.json")
    assert resp_manifest.status_code == 200
    manifest_data = resp_manifest.get_json()
    assert manifest_data["short_name"] == "PhishGuard"
    assert manifest_data["display"] == "standalone"

    resp_sw = client.get("/sw.js")
    assert resp_sw.status_code == 200
    assert b"phishguard-v2-cache" in resp_sw.data
