"""
Advanced URL Feature Extraction & Lexical Analysis Module for PhishGuard V2
Provides robust URL parsing with Public Suffix List (PSL) registered domain extraction,
Unicode homograph / punycode analysis, brand deception detection, and heuristic indicators.
Does NOT make any network connections to target destinations.
"""
import re
import math
import ipaddress
import unicodedata
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional, Tuple
import tldextract

import config

# Initialize offline Public Suffix List extractor (bundled snapshot, zero network access)
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=str(config.REPORTS_DIR / ".tld_cache"), suffix_list_urls=None)


def is_valid_ip(hostname: str) -> int:
    """
    Checks if the hostname is a valid IPv4 or IPv6 address.
    Strips IPv6 brackets and port if present.
    """
    if not hostname:
        return 0
    clean_host = hostname.strip("[]").split(":")[0]
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        # Check for integer/hex/octal IP representations (e.g., 0x7f000001, 2130706433)
        if clean_host.isdigit():
            try:
                val = int(clean_host)
                if 0 <= val <= 4294967295:
                    return 1
            except ValueError:
                pass
        return 0


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string (higher entropy indicates randomized or obfuscated tokens).
    """
    if not text:
        return 0.0
    prob_map = {}
    for char in text:
        prob_map[char] = prob_map.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in prob_map.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def check_homograph_and_punycode(hostname: str) -> Tuple[bool, bool, str]:
    """
    Analyzes hostname for:
    1. Punycode encoding ('xn--' prefix)
    2. Mixed scripts (e.g. Cyrillic/Greek characters embedded in predominantly Latin strings)
    Returns: (is_punycode, has_mixed_scripts, decoded_unicode)
    """
    if not hostname:
        return False, False, ""

    is_punycode = "xn--" in hostname.lower()

    # Try IDNA decoding
    try:
        decoded = hostname.encode("ascii").decode("idna")
    except Exception:
        decoded = hostname

    scripts = set()
    for char in decoded:
        if char.isalpha():
            try:
                script_name = unicodedata.name(char).split()[0]
                scripts.add(script_name)
            except ValueError:
                pass

    has_mixed_scripts = len(scripts) > 1 and ("LATIN" in scripts) and any(s in ("CYRILLIC", "GREEK", "ARABIC", "HEBREW") for s in scripts)

    return is_punycode, has_mixed_scripts, decoded


def extract_url_metadata(url: str) -> Dict[str, Any]:
    """
    Performs deep structural and lexical decomposition of a URL string
    using Public Suffix List rules without network access.
    """
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    url_clean = url.strip()
    if not url_clean:
        return {
            "valid": False,
            "error": "Empty URL input",
            "hostname": "",
            "registered_domain": "",
            "domain_name": "",
            "tld": "",
            "subdomain": "",
            "subdomain_parts": [],
            "path": "",
            "query": "",
            "is_ip": False,
            "is_punycode": False,
            "has_mixed_scripts": False,
            "brand_spoofing": None,
            "is_shortener": False,
            "entropy": 0.0,
            "scheme": "",
            "port": None
        }

    # Ensure parseable scheme
    original_has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_clean))
    url_to_parse = url_clean if original_has_scheme else "http://" + url_clean

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Malformed URL syntax: {str(e)}",
            "hostname": "",
            "registered_domain": "",
            "domain_name": "",
            "tld": "",
            "subdomain": "",
            "subdomain_parts": [],
            "path": "",
            "query": "",
            "is_ip": False,
            "is_punycode": False,
            "has_mixed_scripts": False,
            "brand_spoofing": None,
            "is_shortener": False,
            "entropy": 0.0,
            "scheme": "",
            "port": None
        }

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower() if original_has_scheme else "http"

    # PSL extraction using tldextract
    extracted = _TLD_EXTRACTOR(url_clean)
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
    domain_name = extracted.domain.lower() if extracted.domain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    registered_domain = f"{domain_name}.{suffix}" if (domain_name and suffix) else (domain_name or hostname)

    subdomain_parts = [p for p in subdomain.split(".") if p]
    is_ip = bool(is_valid_ip(hostname))

    # Homograph and punycode check
    is_punycode, has_mixed_scripts, decoded_host = check_homograph_and_punycode(hostname)

    # Shortener check
    is_shortener = (registered_domain in config.SHORTENER_DOMAINS or hostname in config.SHORTENER_DOMAINS)

    # Brand Spoofing Analysis
    # Checks if a high-profile brand name is present in subdomains or path or deceptive domain prefix
    # while the registered domain is NOT owned by that brand
    brand_spoofing = None
    if not is_ip:
        for brand in config.HIGH_PROFILE_BRANDS:
            brand_in_sub = brand in subdomain
            brand_in_domain = brand in domain_name
            brand_in_path = f"/{brand}" in path.lower() or f"{brand}-" in path.lower()

            # If brand is in subdomains or path, but registered domain is NOT official brand domain
            if (brand_in_sub or brand_in_path) and domain_name != brand:
                brand_spoofing = {
                    "brand": brand,
                    "location": "subdomain" if brand_in_sub else "path",
                    "evidence": f"Brand '{brand}' appears in {('subdomain: ' + subdomain) if brand_in_sub else ('path: ' + path)}, but registered domain is '{registered_domain}'."
                }
                break
            elif brand_in_domain and domain_name != brand and ("-" in domain_name or suffix in config.SUSPICIOUS_TLDS):
                brand_spoofing = {
                    "brand": brand,
                    "location": "domain_typosquat",
                    "evidence": f"Brand '{brand}' combined with hyphen/unusual string in domain name '{domain_name}.{suffix}'."
                }
                break

    # Port extraction
    port = None
    try:
        port = parsed.port
    except ValueError:
        port = -1  # Invalid port syntax

    entropy = calculate_shannon_entropy(domain_name or hostname)

    return {
        "valid": True,
        "error": None,
        "original_url": url_clean,
        "hostname": hostname,
        "decoded_hostname": decoded_host,
        "registered_domain": registered_domain,
        "domain_name": domain_name,
        "tld": suffix,
        "subdomain": subdomain,
        "subdomain_parts": subdomain_parts,
        "subdomain_count": len(subdomain_parts),
        "path": path,
        "query": query,
        "scheme": scheme,
        "port": port,
        "is_ip": is_ip,
        "is_punycode": is_punycode,
        "has_mixed_scripts": has_mixed_scripts,
        "brand_spoofing": brand_spoofing,
        "is_shortener": is_shortener,
        "entropy": entropy
    }


def count_subdomains(hostname: str) -> int:
    """
    Calculates subdomain count using Public Suffix List rules.
    """
    if not hostname or is_valid_ip(hostname):
        return 0
    extracted = _TLD_EXTRACTOR(hostname)
    if not extracted.subdomain:
        return 0
    return len([p for p in extracted.subdomain.split(".") if p])


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts canonical lexical and structural features conforming to config.FEATURE_NAMES.
    Guarantees 100% backward compatibility with trained models and existing tests.
    Does NOT make any network connections.
    """
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    url_clean = url.strip()
    if not url_clean:
        return {feat: 0 for feat in config.FEATURE_NAMES}

    original_has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_clean))
    url_to_parse = url_clean if original_has_scheme else "http://" + url_clean

    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        return {feat: 0 for feat in config.FEATURE_NAMES}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Feature 1: Total URL Length
    url_length = len(url_clean)

    # Feature 2: Domain Length
    domain_length = len(hostname)

    # Feature 3: Dot count
    dot_count = url_clean.count(".")

    # Feature 4: Hyphen count
    hyphen_count = url_clean.count("-")

    # Feature 5: Subdomain count (via PSL)
    subdomain_cnt = count_subdomains(hostname)

    # Feature 6: Digit count
    digit_count = sum(c.isdigit() for c in url_clean)

    # Feature 7: Has @ symbol
    has_at_symbol = 1 if "@" in url_clean else 0

    # Feature 8: Presence of IP address as hostname
    has_ip = is_valid_ip(hostname)

    # Feature 9: Is HTTPS in original scheme
    is_https = 1 if url_clean.lower().startswith("https://") else 0

    # Feature 10: Suspicious keyword count
    url_lower = url_clean.lower()
    keyword_count = sum(1 for kw in config.SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Feature 11: Is shortened URL
    extracted = _TLD_EXTRACTOR(hostname)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    is_shortened = 1 if (hostname in config.SHORTENER_DOMAINS or registered_domain in config.SHORTENER_DOMAINS) else 0

    # Feature 12: Slash count
    slash_count = url_clean.count("/")

    # Feature 13: Query param count
    if query:
        query_params = parse_qs(query, keep_blank_values=True)
        query_param_count = len(query_params)
    else:
        query_param_count = 0

    # Feature 14: Has suspicious non-standard port
    has_suspicious_port = 0
    try:
        port = parsed.port
        if port is not None and port not in config.STANDARD_PORTS:
            has_suspicious_port = 1
    except ValueError:
        has_suspicious_port = 1

    # Feature 15: Percent encoding
    has_percent_encoding = 1 if re.search(r"%[0-9a-fA-F]{2}", url_clean) else 0

    # Feature 16: Hyphen in domain
    hyphen_in_domain = 1 if "-" in hostname else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_cnt,
        "digit_count": digit_count,
        "has_at_symbol": has_at_symbol,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "suspicious_keyword_count": keyword_count,
        "is_shortened": is_shortened,
        "slash_count": slash_count,
        "query_param_count": query_param_count,
        "has_suspicious_port": has_suspicious_port,
        "has_percent_encoding": has_percent_encoding,
        "hyphen_in_domain": hyphen_in_domain
    }


def extract_features_vector(url: str) -> List[float]:
    """
    Extracts features as an ordered numerical list conforming strictly
    to config.FEATURE_NAMES order.
    """
    feat_dict = extract_features(url)
    return [float(feat_dict[feat]) for feat in config.FEATURE_NAMES]


def identify_suspicious_indicators(url: str, features: Dict[str, Any],
                                   metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """
    Evaluates extracted features and metadata to identify human-interpretable suspicious indicators.
    Distinguishes observed structural heuristics from conclusive threat matches.
    """
    if metadata is None:
        metadata = extract_url_metadata(url)

    indicators = []

    # 1. IP Address as Hostname
    if features.get("has_ip_address", 0) == 1 or metadata.get("is_ip"):
        indicators.append({
            "title": "IP Address as Hostname",
            "description": "The URL uses a raw numeric IP address instead of a registered domain name.",
            "severity": "high",
            "category": "infrastructure",
            "reason": "Legitimate consumer services almost universally use registered domains rather than raw IP addresses."
        })

    # 2. Credential Masking / @ Symbol
    if features.get("has_at_symbol", 0) == 1:
        indicators.append({
            "title": "URL Contains '@' Symbol",
            "description": "An '@' symbol was detected in the URL structure.",
            "severity": "high",
            "category": "evasion",
            "reason": "Browsers may treat text before '@' as user credentials, obscuring the actual destination hostname."
        })

    # 3. Brand Impersonation / Spoofing in Subdomain or Path
    if metadata.get("brand_spoofing"):
        bs = metadata["brand_spoofing"]
        indicators.append({
            "title": f"Target Brand Mimicking Detected ({bs['brand'].capitalize()})",
            "description": bs["evidence"],
            "severity": "high",
            "category": "deception",
            "reason": "Adversaries embed reputable brand names inside subdomains or paths to trick users regarding site ownership."
        })

    # 4. Homograph or Punycode Detected
    if metadata.get("is_punycode"):
        indicators.append({
            "title": "Punycode (Internationalized Domain) Detected",
            "description": f"Hostname uses punycode encoding: '{metadata.get('hostname')}'. Decodes to: '{metadata.get('decoded_hostname')}'.",
            "severity": "medium",
            "category": "evasion",
            "reason": "Punycode can represent legitimate international characters or deceptive visual homoglyphs."
        })

    if metadata.get("has_mixed_scripts"):
        indicators.append({
            "title": "Mixed-Script Homoglyph Attack Suspected",
            "description": "Hostname combines characters from distinct alphabets (e.g. Cyrillic characters mimicking Latin letters).",
            "severity": "high",
            "category": "evasion",
            "reason": "Mixed scripts are frequently exploited in homograph attacks to visually spoof popular domain names."
        })

    # 5. URL Shortener
    if features.get("is_shortened", 0) == 1 or metadata.get("is_shortener"):
        indicators.append({
            "title": "URL Shortener Detected",
            "description": "The URL uses a known link shortening domain.",
            "severity": "medium",
            "category": "obfuscation",
            "reason": "Shortened links conceal the ultimate landing host and prevent prior inspection by the user."
        })

    # 6. Excessive Subdomains
    sub_count = features.get("subdomain_count", 0) or metadata.get("subdomain_count", 0)
    if sub_count >= 3:
        indicators.append({
            "title": "Excessive Subdomain Levels",
            "description": f"Detected {sub_count} subdomain hierarchy levels in the hostname.",
            "severity": "medium",
            "category": "structure",
            "reason": "Deep subdomain trees are commonly used to craft deceptive domain hierarchies."
        })

    # 7. Suspicious Top-Level Domain (TLD)
    tld = metadata.get("tld", "").lower()
    if tld in config.SUSPICIOUS_TLDS:
        indicators.append({
            "title": f"Abused TLD Observed (.{tld})",
            "description": f"The domain uses the '.{tld}' top-level domain, frequently associated with disposable phishing campaigns.",
            "severity": "low",
            "category": "reputation",
            "reason": "Certain low-cost TLDs exhibit statistically higher prevalence in automated abuse feeds."
        })

    # 8. Hyphen in Domain
    if features.get("hyphen_in_domain", 0) == 1:
        indicators.append({
            "title": "Hyphenated Domain Name",
            "description": "The registered hostname contains hyphens.",
            "severity": "low",
            "category": "lexical",
            "reason": "Adversaries frequently combine authentic brand names with hyphens (e.g. 'paypal-security')."
        })

    # 9. Sensitive Keywords in URL
    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count >= 2:
        indicators.append({
            "title": "Multiple Authentication / Banking Keywords",
            "description": f"URL contains {kw_count} sensitive security or authentication keywords.",
            "severity": "medium",
            "category": "lexical",
            "reason": "Words such as 'login', 'verify', or 'account' in unconventional paths may signal credential harvesting."
        })
    elif kw_count == 1:
        indicators.append({
            "title": "Sensitive Action Keyword Present",
            "description": "Found a sensitive security or authentication keyword in the URL.",
            "severity": "low",
            "category": "lexical",
            "reason": "Such keywords are frequently targeted by deceptive campaigns."
        })

    # 10. Non-Standard Port
    if features.get("has_suspicious_port", 0) == 1:
        indicators.append({
            "title": "Non-Standard Web Port Specified",
            "description": "The URL specifies a custom port number rather than standard web ports (80/443).",
            "severity": "medium",
            "category": "infrastructure",
            "reason": "Public-facing legitimate web services normally use default ports."
        })

    # 11. Unusually Long URL
    if features.get("url_length", 0) > 85:
        indicators.append({
            "title": "Unusually Long URL",
            "description": f"URL length is {features['url_length']} characters, exceeding typical benchmarks.",
            "severity": "low",
            "category": "lexical",
            "reason": "Adversaries sometimes use long URL strings to hide malicious components beyond visible screen width."
        })

    # 12. Percent-Encoded Hex Characters
    if features.get("has_percent_encoding", 0) == 1:
        indicators.append({
            "title": "Percent-Encoded Characters (%xx)",
            "description": "URL includes percent-encoded hex sequences.",
            "severity": "low",
            "category": "obfuscation",
            "reason": "Encoding can be used legitimately, but may also obscure suspicious strings from basic filters."
        })

    # 13. High Entropy Domain (Random Generation Algorithm)
    if metadata.get("entropy", 0.0) >= 4.0:
        indicators.append({
            "title": "High Domain Name Entropy",
            "description": f"Domain name exhibits elevated Shannon entropy ({metadata.get('entropy')} bits/char).",
            "severity": "low",
            "category": "structure",
            "reason": "Elevated entropy suggests procedurally generated or randomized domain names (DGA)."
        })

    # 14. Missing HTTPS Scheme
    if features.get("is_https", 0) == 0:
        indicators.append({
            "title": "Unencrypted HTTP Scheme",
            "description": "URL does not use encrypted HTTPS transport.",
            "severity": "low",
            "category": "transport",
            "reason": "While HTTP alone does not prove phishing, modern legitimate web destinations enforce HTTPS."
        })

    return indicators
