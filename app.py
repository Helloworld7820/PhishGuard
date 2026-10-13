"""
PhishGuard V2 - Flask Web Application and Backend API
Provides web routes and secure JSON endpoints for phishing URL detection,
threat intelligence telemetry, and domain security auditing.
"""
import time
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, send_from_directory, make_response
from markupsafe import escape
import config
from src.predict import predict_url, load_model
from src.evaluate_model import load_saved_metrics
from src.threat_intelligence import get_threat_intel_status
from src.scan_history import get_scan_history, get_scan_stats, clear_scan_history
from src.model_registry import get_registered_model_metadata

app = Flask(__name__)

# Security: Limit maximum incoming request body size to 32 KB
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

# Simple In-Memory Rate Limiting (60 requests per minute per IP)
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = 60
_request_records = defaultdict(list)


def is_rate_limited(client_ip: str) -> bool:
    """Checks whether the client IP has exceeded the request threshold."""
    now = time.time()
    timestamps = _request_records[client_ip]
    # Prune timestamps older than window
    _request_records[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_request_records[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return True
    _request_records[client_ip].append(now)
    return False


def validate_url_input(url_str: str) -> tuple[bool, str]:
    """Validates submitted URL string before processing."""
    if not url_str or not isinstance(url_str, str):
        return False, "Please enter a valid URL."
    cleaned = url_str.strip()
    if len(cleaned) == 0:
        return False, "URL input cannot be blank or whitespace."
    if len(cleaned) > 2048:
        return False, "URL exceeds the maximum permissible length of 2048 characters."
    # Check for basic invalid characters like newlines or control characters
    if any(ord(c) < 32 for c in cleaned):
        return False, "URL contains illegal control characters."
    return True, cleaned


# ---------------------------------------------------------
# Web Page Routes
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    """Renders the Home / URL Scanner page."""
    return render_template("index.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Renders the Model & Training Evaluation Dashboard with live threat intel status."""
    try:
        metrics = load_saved_metrics()
    except Exception:
        metrics = None

    providers_status = get_threat_intel_status()
    scan_stats = get_scan_stats()
    scan_history = get_scan_history()
    model_metadata = get_registered_model_metadata()

    return render_template(
        "dashboard.html",
        metrics=metrics,
        providers_status=providers_status,
        scan_stats=scan_stats,
        scan_history=scan_history,
        model_metadata=model_metadata
    )


@app.route("/about", methods=["GET"])
def about():
    """Renders the Project Information and Educational page."""
    return render_template("about.html")


@app.route("/analyze", methods=["POST"])
def analyze_form():
    """Handles standard browser form submission and renders results page."""
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        return render_template(
            "index.html",
            error_message="Too many requests. Please wait a few moments before scanning again."
        ), 429

    url_input = request.form.get("url", "")
    is_valid, validation_msg = validate_url_input(url_input)
    if not is_valid:
        return render_template("index.html", error_message=validation_msg), 400

    try:
        result = predict_url(validation_msg)
        return render_template("results.html", result=result)
    except FileNotFoundError:
        return render_template(
            "index.html",
            error_message="Model artifacts not found. Please ensure the model has been trained."
        ), 503
    except Exception:
        return render_template(
            "index.html",
            error_message="An unexpected error occurred while analyzing the URL."
        ), 500


# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    JSON API Endpoint for URL Analysis.
    Expects JSON body: {"url": "https://example.com"}
    """
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        return jsonify({
            "status": "error",
            "message": "Rate limit exceeded. Please wait a moment before trying again."
        }), 429

    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "Request content type must be application/json"
        }), 400

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "status": "error",
            "message": "Missing required field 'url' in request payload."
        }), 400

    url_input = data.get("url")
    is_valid, validation_msg = validate_url_input(url_input)
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": validation_msg
        }), 400

    try:
        analysis = predict_url(validation_msg)
        return jsonify({
            "status": "success",
            "data": analysis
        }), 200
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": "Model not loaded. Ensure train_model.py has run."
        }), 503
    except Exception:
        return jsonify({
            "status": "error",
            "message": "Internal error occurred during URL feature processing."
        }), 500


@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint reporting application and model loading status."""
    model_loaded = False
    try:
        load_model()
        model_loaded = True
    except Exception:
        model_loaded = False

    metrics_available = config.METRICS_PATH.exists()
    providers = get_threat_intel_status()

    return jsonify({
        "status": "healthy" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "metrics_available": metrics_available,
        "version": config.VERSION,
        "threat_intel_providers": providers,
        "domain_signals_enabled": config.ENABLE_DOMAIN_SIGNALS,
        "network_access": "controlled (DNS & TLS headers only; zero HTTP page fetching)"
    }), 200


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    """Returns actual persisted model evaluation metrics and feature importances."""
    try:
        metrics = load_saved_metrics()
        return jsonify({
            "status": "success",
            "data": metrics
        }), 200
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": "Evaluation metrics not found. Model has not been trained yet."
        }), 404
    except Exception:
        return jsonify({
            "status": "error",
            "message": "Failed to load evaluation metrics."
        }), 500


@app.route("/api/providers", methods=["GET"])
def api_providers():
    """Returns configuration status of threat intelligence providers."""
    return jsonify({
        "status": "success",
        "providers": get_threat_intel_status()
    }), 200


@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns local privacy-sanitized scan history and statistics."""
    return jsonify({
        "status": "success",
        "statistics": get_scan_stats(),
        "history": get_scan_history()
    }), 200


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears local scan history upon user request."""
    clear_scan_history()
    return jsonify({
        "status": "success",
        "message": "Scan history cleared successfully."
    }), 200


# ---------------------------------------------------------
# PWA & Android Integration Routes
# ---------------------------------------------------------

@app.route("/manifest.json", methods=["GET"])
def manifest():
    """Serves Web App Manifest for Android PWA installability."""
    return send_from_directory("static", "manifest.json", mimetype="application/manifest+json")


@app.route("/sw.js", methods=["GET"])
def service_worker():
    """Serves PWA service worker."""
    response = make_response(send_from_directory("static", "sw.js", mimetype="application/javascript"))
    response.headers["Service-Worker-Allowed"] = "/"
    return response


# ---------------------------------------------------------
# HTTP Error Handlers
# ---------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "Endpoint not found"}), 404
    return render_template("index.html", error_message="Requested page was not found."), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "Payload exceeds maximum allowed size"}), 413
    return render_template("index.html", error_message="Submitted payload is too large."), 413


@app.errorhandler(500)
def internal_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500
    return render_template("index.html", error_message="An internal server error occurred."), 500


if __name__ == "__main__":
    print("==================================================")
    print("  PhishGuard V2 Web Application Starting Locally   ")
    print("  Access dashboard: http://127.0.0.1:5000         ")
    print("==================================================")
    app.run(host="127.0.0.1", port=5000, debug=False)
