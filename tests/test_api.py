"""
Integration and API endpoint tests for PhishGuard.
Verifies Flask routing, model inference, prediction payloads, and error scenarios.
"""
from unittest.mock import patch
from pathlib import Path
import pytest
from app import app
from src.predict import load_model, predict_url
import config


@pytest.fixture
def client():
    """Configures test client for Flask application."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_model_loading():
    """Verify that the trained Random Forest model and feature list load successfully."""
    model, features = load_model()
    assert model is not None
    assert isinstance(features, list)
    assert len(features) == len(config.FEATURE_NAMES)


def test_predict_url_output_structure():
    """Verify the schema, data types, and bounds of prediction results."""
    res = predict_url("https://google.com")
    assert isinstance(res, dict)
    assert "url" in res
    assert res["prediction"] in ["PHISHING", "LIKELY LEGITIMATE"]
    assert 0.0 <= res["risk_score"] <= 100.0
    assert res["risk_category"] in ["Low", "Medium", "High"]
    assert 0.0 <= res["phishing_probability"] <= 1.0
    assert 0.0 <= res["legitimate_probability"] <= 1.0
    assert "features" in res
    assert isinstance(res["indicators"], list)
    assert "recommendation" in res
    assert "disclaimer" in res


def test_home_route(client):
    """Verify Home URL scanner page loads with status 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    assert b"Detect Phishing" in response.data


def test_dashboard_route(client):
    """Verify Model Metrics dashboard loads with status 200."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Model Architecture" in response.data
    assert b"Confusion Matrix" in response.data


def test_about_route(client):
    """Verify About page loads with status 200."""
    response = client.get("/about")
    assert response.status_code == 200
    assert b"About" in response.data
    assert b"PhishGuard" in response.data


def test_api_health_endpoint(client):
    """Verify /api/health returns valid JSON with model loaded status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] in ["healthy", "degraded"]
    assert data["model_loaded"] is True
    assert "version" in data


def test_api_metrics_endpoint(client):
    """Verify /api/metrics returns real persisted model metrics."""
    response = client.get("/api/metrics")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    data = payload["data"]
    assert "primary_metrics" in data
    assert "confusion_matrix" in data["primary_metrics"]
    assert "feature_importance" in data
    assert "model_comparison" in data


def test_api_analyze_valid_url(client):
    """Verify /api/analyze handles valid JSON payload and returns prediction."""
    payload = {"url": "http://paypal-verification-update-portal.xyz/login"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "data" in data
    assert "risk_score" in data["data"]
    assert data["data"]["prediction"] in ["PHISHING", "LIKELY LEGITIMATE"]


def test_api_analyze_missing_url(client):
    """Verify /api/analyze rejects missing 'url' key."""
    response = client.post("/api/analyze", json={"foo": "bar"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"


def test_api_analyze_invalid_content_type(client):
    """Verify /api/analyze requires application/json."""
    response = client.post("/api/analyze", data="plain text body")
    assert response.status_code == 400


def test_analyze_form_post(client):
    """Verify browser form submission /analyze endpoint returns rendered results page."""
    response = client.post("/analyze", data={"url": "https://wikipedia.org"})
    assert response.status_code == 200
    assert b"Assessment Report" in response.data or b"Analysis Result" in response.data
    assert b"wikipedia.org" in response.data


def test_missing_model_handling(client):
    """Verify application returns friendly error if model artifact is missing."""
    with patch("src.predict.load_model", side_effect=FileNotFoundError("Mock model missing")):
        response = client.post("/api/analyze", json={"url": "https://example.com"})
        assert response.status_code == 503
        data = response.get_json()
        assert "not loaded" in data["message"].lower() or "model" in data["message"].lower()
