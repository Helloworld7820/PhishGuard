"""
Domain and Certificate Signals Module for PhishGuard V2
Provides safe, controlled inspection of domain DNS resolution and SSL/TLS certificate metadata.
Strictly restricted to DNS queries and TLS SNI handshakes on port 443.
NEVER issues HTTP GET/POST requests, follows redirects, or downloads webpage content.
"""
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import config
from src.feature_extraction import extract_url_metadata


def check_dns_resolution(hostname: str, timeout: float = config.DOMAIN_SIGNALS_TIMEOUT) -> Dict[str, Any]:
    """
    Checks whether a domain name successfully resolves to IPv4/IPv6 addresses via system DNS.
    Returns resolution status, resolved IP addresses, or unknown state.
    """
    if not hostname:
        return {
            "resolved": False,
            "status": "unknown",
            "ips": [],
            "details": "No hostname provided for DNS resolution."
        }

    # If hostname is already a raw IP
    try:
        socket.inet_aton(hostname)
        return {
            "resolved": True,
            "status": "raw_ip",
            "ips": [hostname],
            "details": "Hostname is already a raw IPv4 address."
        }
    except socket.error:
        pass

    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set([item[4][0] for item in addr_info]))
        return {
            "resolved": True,
            "status": "resolved",
            "ips": ips[:5],  # Limit to first 5 IPs
            "details": f"Successfully resolved to {len(ips)} IP address(es)."
        }
    except (socket.gaierror, socket.herror) as e:
        return {
            "resolved": False,
            "status": "unresolved",
            "ips": [],
            "details": f"Domain does not resolve via DNS ({type(e).__name__}). May be inactive or recently dropped."
        }
    except socket.timeout:
        return {
            "resolved": False,
            "status": "unknown",
            "ips": [],
            "details": f"DNS query timed out after {timeout}s."
        }
    except Exception as e:
        return {
            "resolved": False,
            "status": "unknown",
            "ips": [],
            "details": f"DNS check encountered error: {str(e)}"
        }
    finally:
        socket.setdefaulttimeout(orig_timeout)


def check_tls_certificate(hostname: str, port: int = 443,
                          timeout: float = config.DOMAIN_SIGNALS_TIMEOUT) -> Dict[str, Any]:
    """
    Performs a safe TLS SNI handshake to inspect certificate headers only.
    DOES NOT send any HTTP application-layer data or fetch HTML.
    """
    if not hostname or hostname in ("localhost", "127.0.0.1"):
        return {
            "status": "unknown",
            "available": False,
            "details": "TLS inspection skipped for local or empty hostname."
        }

    context = ssl.create_default_context()
    orig_timeout = socket.getdefaulttimeout()

    try:
        socket.setdefaulttimeout(timeout)
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return {
                "status": "unknown",
                "available": False,
                "details": "No peer certificate returned by server."
            }

        # Extract issuer common name
        issuer_items = cert.get("issuer", ())
        issuer_dict = {}
        for rdn in issuer_items:
            for key, value in rdn:
                issuer_dict[key] = value
        issuer_name = issuer_dict.get("commonName") or issuer_dict.get("organizationName") or "Unknown Issuer"

        # Expiry date parsing
        not_after_str = cert.get("notAfter", "")
        expires_at = None
        is_expired = False
        days_left = None
        if not_after_str:
            try:
                # Format: 'May 10 12:00:00 2026 GMT'
                dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                expires_at = dt.isoformat()
                diff = dt - datetime.now(timezone.utc)
                days_left = diff.days
                if days_left < 0:
                    is_expired = True
            except Exception:
                pass

        # Subject Alternative Names (SAN)
        san_entries = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]

        return {
            "status": "valid" if not is_expired else "expired",
            "available": True,
            "issuer": issuer_name,
            "expires_at": expires_at,
            "days_remaining": days_left,
            "is_expired": is_expired,
            "san_count": len(san_entries),
            "details": f"Valid certificate issued by {issuer_name}. Expires in {days_left} days." if not is_expired else f"Certificate is expired (issuer: {issuer_name})."
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "status": "invalid_certificate",
            "available": True,
            "issuer": "Untrusted / Self-Signed",
            "details": f"Certificate verification failed ({e.verify_message})."
        }
    except ssl.SSLError as e:
        return {
            "status": "tls_error",
            "available": False,
            "details": f"TLS handshake failed: {type(e).__name__}."
        }
    except (socket.timeout, TimeoutError):
        return {
            "status": "unknown",
            "available": False,
            "details": f"TLS handshake timed out after {timeout}s."
        }
    except (ConnectionRefusedError, socket.gaierror, OSError) as e:
        return {
            "status": "unknown",
            "available": False,
            "details": f"Port 443 connection failed or unreachable ({type(e).__name__})."
        }
    finally:
        socket.setdefaulttimeout(orig_timeout)


def evaluate_domain_signals(url: str, enable_network: bool = config.ENABLE_DOMAIN_SIGNALS) -> Dict[str, Any]:
    """
    Orchestrates safe domain and certificate telemetry.
    If network signals are disabled or unavailable, returns structured 'unknown' signals
    without treating missing information as evidence of malice or safety.
    """
    meta = extract_url_metadata(url)
    hostname = meta.get("hostname", "")

    if not enable_network or not hostname:
        return {
            "enabled": False,
            "dns": {
                "status": "unknown",
                "resolved": False,
                "details": "DNS checking disabled in configuration." if not enable_network else "No hostname to resolve."
            },
            "tls": {
                "status": "unknown",
                "available": False,
                "details": "TLS inspection disabled in configuration." if not enable_network else "No hostname."
            },
            "signals_evaluated": 0,
            "unknown_signals": ["dns_resolution", "tls_certificate", "whois_registration_age"]
        }

    dns_info = check_dns_resolution(hostname)
    tls_info = check_tls_certificate(hostname)

    unknown_signals = []
    if dns_info["status"] == "unknown":
        unknown_signals.append("dns_resolution")
    if tls_info["status"] == "unknown":
        unknown_signals.append("tls_certificate")
    unknown_signals.append("whois_registration_age")  # Marked as unknown by policy unless verified RDAP is configured

    return {
        "enabled": True,
        "dns": dns_info,
        "tls": tls_info,
        "signals_evaluated": 2,
        "unknown_signals": unknown_signals,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
