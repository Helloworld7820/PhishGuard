"""
Evidence-Based Decision Engine for PhishGuard V2
Aggregates independent evidence streams:
1. Threat intelligence matches (Google Safe Browsing, PhishTank, Local feeds)
2. Machine learning model prediction score (Random Forest class probability)
3. Structural URL heuristics (homographs, brand spoofing, IP hostnames, shorteners)
4. Domain signals (DNS resolution, certificate validity, unknown flags)

Produces one of four authoritative verdicts:
- PHISHING DETECTED
- SUSPICIOUS
- NO KNOWN THREAT DETECTED
- INCONCLUSIVE
"""
from typing import Dict, Any, List, Optional
import config


def compute_final_verdict(
    url: str,
    model_score: float,
    indicators: List[Dict[str, Any]],
    threat_intel: Dict[str, Any],
    domain_signals: Dict[str, Any],
    metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates multi-source evidence and outputs a transparent, defensible verdict.
    """
    confirmed_threat = threat_intel.get("confirmed_threat", False)
    threat_types = threat_intel.get("threat_types", [])
    
    # Calculate indicator severity counts
    high_sev_indicators = [i for i in indicators if i.get("severity") == "high"]
    med_sev_indicators = [i for i in indicators if i.get("severity") == "medium"]
    low_sev_indicators = [i for i in indicators if i.get("severity") == "low"]

    dns_resolved = domain_signals.get("dns", {}).get("resolved", True)
    dns_status = domain_signals.get("dns", {}).get("status", "unknown")
    is_valid_url = metadata.get("valid", True)
    
    reasons: List[str] = []
    verdict: str = config.VERDICT_NO_KNOWN_THREAT
    confidence: str = "Medium"
    status_color: str = "success"

    # 1. Condition: Malformed or Invalid URL syntax
    if not is_valid_url:
        verdict = config.VERDICT_INCONCLUSIVE
        confidence = "Low"
        status_color = "secondary"
        reasons.append(f"URL syntax could not be reliably parsed: {metadata.get('error', 'Malformed structure')}.")

    # 2. Condition: Confirmed Threat Intelligence Match
    elif confirmed_threat:
        verdict = config.VERDICT_PHISHING
        confidence = "Very High"
        status_color = "danger"
        reasons.append(f"Confirmed malicious destination flagged by active threat intelligence: {', '.join(threat_types)}.")

    # 3. Condition: Severe Structural Deception (Homoglyph, Brand Impersonation, or IP + Credentials)
    elif metadata.get("has_mixed_scripts") or (metadata.get("brand_spoofing") and model_score >= 60.0):
        verdict = config.VERDICT_PHISHING
        confidence = "High"
        status_color = "danger"
        if metadata.get("has_mixed_scripts"):
            reasons.append("Visual homoglyph / mixed-script deception detected in hostname.")
        if metadata.get("brand_spoofing"):
            reasons.append(f"High-confidence brand spoofing observed: {metadata['brand_spoofing']['evidence']}.")

    # 4. Condition: High Model Risk Score (>= 75.0) with at least 1 high or 2 medium indicators
    elif model_score >= 75.0 and (len(high_sev_indicators) >= 1 or len(med_sev_indicators) >= 2):
        verdict = config.VERDICT_PHISHING
        confidence = "High"
        status_color = "danger"
        reasons.append(f"Model-estimated risk score is very high ({model_score}/100) supported by {len(high_sev_indicators) + len(med_sev_indicators)} prominent structural indicators.")

    # 5. Condition: Suspicious Elevated Risk (Score between 45.0 and 75.0, or multiple indicators)
    elif model_score >= 45.0 or len(high_sev_indicators) >= 1 or len(med_sev_indicators) >= 2 or metadata.get("brand_spoofing"):
        verdict = config.VERDICT_SUSPICIOUS
        confidence = "Medium"
        status_color = "warning"
        if model_score >= 45.0:
            reasons.append(f"Model-estimated risk is elevated ({model_score}/100).")
        if metadata.get("brand_spoofing"):
            reasons.append(f"Target brand mimicking detected in URL hierarchy ({metadata['brand_spoofing']['brand']}).")
        if high_sev_indicators:
            reasons.append(f"Detected {len(high_sev_indicators)} high-severity structural heuristic(s): {high_sev_indicators[0]['title']}.")
        if med_sev_indicators:
            reasons.append(f"Detected {len(med_sev_indicators)} medium-severity indicator(s) (e.g. shorteners or excessive subdomains).")

    # 6. Condition: Unresolvable Domain with Conflicting Evidence
    elif dns_status == "unresolved" and model_score > 30.0:
        verdict = config.VERDICT_INCONCLUSIVE
        confidence = "Low"
        status_color = "secondary"
        reasons.append("Domain name does not currently resolve in public DNS and model exhibits borderline suspicion. Threat status cannot be conclusively verified.")

    # 7. Condition: No Known Threat Detected (Checks clear)
    else:
        verdict = config.VERDICT_NO_KNOWN_THREAT
        confidence = "Medium"
        status_color = "success"
        reasons.append("No matches in configured threat intelligence databases.")
        reasons.append(f"Model risk estimation is low ({model_score}/100).")
        reasons.append("URL conforms to standard lexical domain patterns without detected brand spoofing or homoglyph anomalies.")

    # Generate Actionable Security Recommendations
    recommendation = generate_recommendation(verdict, model_score)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "status_color": status_color,
        "reasons": reasons,
        "recommendation": recommendation,
        "model_score": model_score,
        "confirmed_threat": confirmed_threat,
        "high_severity_indicators_count": len(high_sev_indicators),
        "medium_severity_indicators_count": len(med_sev_indicators),
        "low_severity_indicators_count": len(low_sev_indicators)
    }


def generate_recommendation(verdict: str, model_score: float) -> str:
    """Returns contextual safety advice strictly tailored to the verdict."""
    if verdict == config.VERDICT_PHISHING:
        return (
            "CRITICAL WARNING: DO NOT VISIT OR ENTER CREDENTIALS. "
            "Strong evidence of deceptive intent or verified threat intelligence match. "
            "Never submit passwords, OTPs, credit cards, or personal identifiers. Close the window immediately."
        )
    elif verdict == config.VERDICT_SUSPICIOUS:
        return (
            "EXERCISE HEIGHTENED CAUTION: Elevated risk detected. "
            "The URL exhibits anomalous or deceptive structures (e.g., brand-mimicking strings, unverified shorteners, or sensitive auth keywords). "
            "Verify the destination independently through official corporate bookmarks or search engines before interacting."
        )
    elif verdict == config.VERDICT_INCONCLUSIVE:
        return (
            "INCONCLUSIVE ASSESSMENT: Available data is insufficient or contradictory to render a conclusive verdict. "
            "Treat with caution: avoid submitting confidential authentication credentials until the domain authenticity is manually validated."
        )
    else:  # NO KNOWN THREAT DETECTED
        return (
            "NO KNOWN THREAT DETECTED: Automated checks identified no known threat markers or malicious structural patterns. "
            "IMPORTANT: This is NOT a guarantee of complete safety. Automated tools can miss novel zero-day campaigns. "
            "Always verify browser padlock certificates and enforce multi-factor authentication (MFA)."
        )
