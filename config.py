"""
PhishGuard V2 Configuration Module
Contains system constants, file paths, model parameters, threat intelligence settings,
and heuristic rules.
"""
import os
from pathlib import Path

# Load optional .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Application Version
VERSION = "2.0.0"

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Dataset Paths
DATASET_CSV_PATH = DATA_DIR / "dataset.csv"
SYNTHETIC_DATASET_CSV_PATH = DATA_DIR / "synthetic_dataset.csv"

# Model Artifact Paths
MODEL_PATH = MODELS_DIR / "phishguard_rf_model.joblib"
METRICS_PATH = REPORTS_DIR / "model_metrics.json"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.joblib"
MODEL_REGISTRY_PATH = REPORTS_DIR / "model_registry.json"

# Threat Intelligence & Scan Cache Paths
THREAT_INTEL_CACHE_PATH = REPORTS_DIR / "threat_intel_cache.json"
SCAN_HISTORY_PATH = REPORTS_DIR / "scan_history.json"

# Model Hyperparameters
MODEL_CONFIG = {
    "n_estimators": 200,
    "max_depth": 12,
    "random_state": 42,
    "class_weight": "balanced",
    "n_jobs": -1
}

TEST_SPLIT_RATIO = 0.20
RANDOM_SEED = 42

# Risk Score Thresholds
RISK_THRESHOLDS = {
    "LOW": (0, 39),
    "MEDIUM": (40, 69),
    "HIGH": (70, 100)
}

# Standardized Decision Engine Verdicts
VERDICT_PHISHING = "PHISHING DETECTED"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_NO_KNOWN_THREAT = "NO KNOWN THREAT DETECTED"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"

# Threat Intelligence API Configuration
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
OPENPHISH_API_KEY = os.getenv("OPENPHISH_API_KEY", "").strip()

THREAT_INTEL_TIMEOUT = float(os.getenv("THREAT_INTEL_TIMEOUT", "3.0"))
THREAT_INTEL_CACHE_TTL = int(os.getenv("THREAT_INTEL_CACHE_TTL", "3600"))

# Domain Signals Configuration
ENABLE_DOMAIN_SIGNALS = os.getenv("ENABLE_DOMAIN_SIGNALS", "true").lower() in ("true", "1", "yes")
DOMAIN_SIGNALS_TIMEOUT = float(os.getenv("DOMAIN_SIGNALS_TIMEOUT", "3.0"))

# Scan History Configuration
ENABLE_SCAN_HISTORY = os.getenv("ENABLE_SCAN_HISTORY", "true").lower() in ("true", "1", "yes")
SCAN_HISTORY_MAX = int(os.getenv("SCAN_HISTORY_MAX", "50"))

# Suspicious keywords commonly observed in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "banking", "secure", "account",
    "signin", "confirm", "password", "authenticate", "webscr",
    "ebayisapi", "paypal", "appleid", "recovery", "validation",
    "service", "billing", "support", "wallet", "unlock", "alert",
    "free", "gift", "bonus", "reward", "security", "token", "claim",
    "passcode", "credential", "session", "authorize", "redirect"
]

# High-Profile Brand Targets frequently targeted in phishing spoofs
HIGH_PROFILE_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "facebook", "instagram",
    "whatsapp", "twitter", "dropbox", "github", "ebay", "coinbase",
    "binance", "metamask", "steam", "linkedin", "dhl", "fedex", "usps",
    "adobe", "yahoo", "outlook", "icloud"
]

# Common URL Shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "rebrand.ly", "tiny.cc", "cutt.ly", "shorturl.at",
    "rb.gy", "bl.ink", "lnkd.in", "s.id", "soo.gd", "clck.ru", "qr.ae"
}

# Suspicious Top-Level Domains commonly abused in bulk automated phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "info", "online", "site", "tk", "cf", "club", "buzz",
    "work", "gq", "ml", "cc", "icu", "cam", "fit", "rest", "monster", "cfd"
}

# Standard web ports (anything else is suspicious for public web)
STANDARD_PORTS = {80, 443}

# Canonical Feature List (Used across feature extraction, training, and inference)
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "subdomain_count",
    "digit_count",
    "has_at_symbol",
    "has_ip_address",
    "is_https",
    "suspicious_keyword_count",
    "is_shortened",
    "slash_count",
    "query_param_count",
    "has_suspicious_port",
    "has_percent_encoding",
    "hyphen_in_domain"
]
