"""
PhishGuard V2 Prediction & Multi-Layer Detection Orchestrator
Coordinates:
1. Public Suffix List metadata extraction (hostname, registered domain, punycode, brand spoofing)
2. Lexical feature vector extraction
3. Random Forest model inference
4. Real-world threat intelligence checks (Google Safe Browsing, PhishTank, Local signatures)
5. Safe domain signals (DNS resolution, TLS certificate metadata)
6. Evidence-based decision engine verdict aggregation
7. Privacy-preserving scan history logging
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import joblib
import numpy as np

import config
from src.feature_extraction import (
    extract_features,
    extract_features_vector,
    extract_url_metadata,
    identify_suspicious_indicators
)
from src.threat_intelligence import check_threat_intelligence
from src.domain_signals import evaluate_domain_signals
from src.decision_engine import compute_final_verdict
from src.scan_history import record_scan

# Global cached model and feature names
_CACHED_MODEL = None
_CACHED_FEATURE_NAMES = None


def load_model(force_reload: bool = False):
    """
    Loads trained Random Forest model and feature names from disk.
    Caches model in memory for high-performance sub-millisecond inference.
    """
    global _CACHED_MODEL, _CACHED_FEATURE_NAMES

    if _CACHED_MODEL is not None and not force_reload:
        return _CACHED_MODEL, _CACHED_FEATURE_NAMES

    if not config.MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found at {config.MODEL_PATH}. "
            "Please run 'python -m src.train_model' to generate model artifacts."
        )

    _CACHED_MODEL = joblib.load(config.MODEL_PATH)

    if config.FEATURE_NAMES_PATH.exists():
        _CACHED_FEATURE_NAMES = joblib.load(config.FEATURE_NAMES_PATH)
    else:
        _CACHED_FEATURE_NAMES = config.FEATURE_NAMES

    return _CACHED_MODEL, _CACHED_FEATURE_NAMES


def get_risk_category(risk_score: float) -> str:
    """Categorizes numerical risk score into Low, Medium, or High."""
    if risk_score <= config.RISK_THRESHOLDS["LOW"][1]:
        return "Low"
    elif risk_score <= config.RISK_THRESHOLDS["MEDIUM"][1]:
        return "Medium"
    else:
        return "High"


def predict_url(url: str, enable_external_checks: bool = True) -> Dict[str, Any]:
    """
    Executes full multi-layer inspection on submitted URL:
    - Layer A: Advanced URL parsing (PSL, homographs, brand deception)
    - Layer B: Real-world Threat Intelligence (GSB, PhishTank, Local feeds)
    - Layer C: Safe Domain & Certificate Signals (DNS, TLS SNI headers)
    - Layer D: Machine Learning (Random Forest predict_proba)
    - Layer E: Evidence-based Decision Engine (4-state standardized verdict)
    """
    model, feature_names = load_model()

    # 1. Layer A: Metadata and Feature Extraction
    metadata = extract_url_metadata(url)
    features_dict = extract_features(url)
    features_vec = [float(features_dict[feat]) for feat in feature_names]
    X_input = np.array([features_vec], dtype=np.float32)

    # 2. Layer D: Model Inference
    probabilities = model.predict_proba(X_input)[0]
    # Class 0 = Legitimate, Class 1 = Phishing
    phishing_prob = float(probabilities[1])
    model_score = round(phishing_prob * 100.0, 1)

    # 3. Indicators Gathering
    indicators = identify_suspicious_indicators(url, features_dict, metadata)

    # 4. Layer B: Threat Intelligence Lookups
    threat_intel = check_threat_intelligence(url)

    # 5. Layer C: Domain and Certificate Signals
    domain_signals = evaluate_domain_signals(url, enable_network=enable_external_checks)

    # 6. Layer E: Evidence Aggregation Decision Engine
    decision = compute_final_verdict(
        url=url,
        model_score=model_score,
        indicators=indicators,
        threat_intel=threat_intel,
        domain_signals=domain_signals,
        metadata=metadata
    )

    verdict = decision["verdict"]
    status_color = decision["status_color"]
    confidence = decision["confidence"]
    reasons = decision["reasons"]
    recommendation = decision["recommendation"]
    risk_category = get_risk_category(model_score)

    # Backward compatibility with v1 prediction labels
    if verdict == config.VERDICT_PHISHING:
        legacy_prediction = "PHISHING"
    elif verdict == config.VERDICT_SUSPICIOUS:
        legacy_prediction = "SUSPICIOUS"
    elif verdict == config.VERDICT_INCONCLUSIVE:
        legacy_prediction = "INCONCLUSIVE"
    else:
        legacy_prediction = "LIKELY LEGITIMATE"

    # Compile unknown / unavailable checks list
    unknown_checks = list(domain_signals.get("unknown_signals", []))
    for p in threat_intel.get("provider_results", []):
        if p["status"] in ("unconfigured", "unavailable", "rate_limited"):
            unknown_checks.append(f"threat_intel_{p['provider'].lower().replace(' ', '_')}")

    # Record in local scan history (privacy-sanitized)
    record_scan(url, verdict, model_score, status_color)

    scan_timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "url": url,
        "prediction": legacy_prediction,
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": model_score,
        "risk_category": risk_category,
        "phishing_probability": round(phishing_prob, 4),
        "legitimate_probability": round(float(probabilities[0]), 4),
        "status_color": status_color,
        "reasons": reasons,
        "recommendation": recommendation,
        "features": features_dict,
        "metadata": metadata,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "threat_intelligence": threat_intel,
        "domain_signals": domain_signals,
        "unknown_signals": unknown_checks,
        "scan_timestamp": scan_timestamp,
        "disclaimer": (
            "Disclaimer: Predictions and verdicts are algorithmic estimates derived from URL structure, "
            "available threat intelligence, and domain signals without executing or visiting destination content. "
            "Never treat any automated classification as an absolute guarantee of safety."
        )
    }
