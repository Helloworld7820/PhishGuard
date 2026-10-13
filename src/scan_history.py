"""
Privacy-Conscious Scan History Module for PhishGuard V2
Provides optional, locally retained scan logs for the dashboard.
Strips user credentials, tokens, sensitive query strings, and cookies before persistence.
Enforces fixed retention limits and supports full clearing.
"""
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime, timezone
from typing import Dict, Any, List
import config


def sanitize_url_for_history(url: str) -> str:
    """
    Sanitizes URL to remove passwords, basic auth, and sensitive query parameter values
    (e.g., token, password, auth, key, secret, session).
    """
    if not url:
        return ""
    try:
        # Prepend scheme if missing for urlparse
        has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
        to_parse = url if has_scheme else "http://" + url
        parsed = urlparse(to_parse)

        # Redact credentials if in netloc (e.g., user:pass@host)
        netloc = parsed.netloc
        if "@" in netloc:
            host_part = netloc.split("@")[-1]
            netloc = f"***:***@{host_part}"

        # Redact sensitive query parameters
        sensitive_keys = {"token", "auth", "key", "password", "pass", "pwd", "secret", "session", "api_key", "access_token", "code"}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            sanitized_qs = {}
            for k, v in qs.items():
                if k.lower() in sensitive_keys:
                    sanitized_qs[k] = ["REDACTED"]
                else:
                    sanitized_qs[k] = v
            new_query = urlencode(sanitized_qs, doseq=True)
        else:
            new_query = ""

        # Reconstruct sanitized URL
        path = parsed.path
        reconstructed = f"{parsed.scheme}://{netloc}{path}"
        if new_query:
            reconstructed += f"?{new_query}"
        return reconstructed
    except Exception:
        return "https://[sanitized-url]"


class ScanHistoryManager:
    """
    Manages local, privacy-safe scan history records.
    """
    def __init__(self, history_file=config.SCAN_HISTORY_PATH, max_entries=config.SCAN_HISTORY_MAX):
        self.history_file = history_file
        self.max_entries = max_entries

    def _read_records(self) -> List[Dict[str, Any]]:
        if not config.ENABLE_SCAN_HISTORY or not self.history_file.exists():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_records(self, records: List[Dict[str, Any]]):
        if not config.ENABLE_SCAN_HISTORY:
            return
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(records[:self.max_entries], f, indent=2)
        except Exception:
            pass

    def add_scan(self, url: str, verdict: str, risk_score: float, status_color: str):
        """Records a new sanitized scan entry."""
        if not config.ENABLE_SCAN_HISTORY:
            return

        records = self._read_records()
        sanitized_url = sanitize_url_for_history(url)

        entry = {
            "url": sanitized_url,
            "verdict": verdict,
            "risk_score": risk_score,
            "status_color": status_color,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Prepend latest
        records.insert(0, entry)
        self._write_records(records[:self.max_entries])

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns recent scan history."""
        return self._read_records()

    def get_statistics(self) -> Dict[str, Any]:
        """Calculates real scan telemetry across recorded history."""
        records = self._read_records()
        total = len(records)
        verdict_counts = {
            config.VERDICT_PHISHING: 0,
            config.VERDICT_SUSPICIOUS: 0,
            config.VERDICT_NO_KNOWN_THREAT: 0,
            config.VERDICT_INCONCLUSIVE: 0
        }
        for r in records:
            v = r.get("verdict")
            if v in verdict_counts:
                verdict_counts[v] += 1
            else:
                verdict_counts[v] = verdict_counts.get(v, 0) + 1

        return {
            "total_scans": total,
            "verdicts": verdict_counts,
            "enabled": config.ENABLE_SCAN_HISTORY
        }

    def clear(self):
        """Clears all scan history."""
        self._write_records([])


# Global history manager
_SCAN_HISTORY = ScanHistoryManager()


def record_scan(url: str, verdict: str, risk_score: float, status_color: str):
    _SCAN_HISTORY.add_scan(url, verdict, risk_score, status_color)


def get_scan_history() -> List[Dict[str, Any]]:
    return _SCAN_HISTORY.get_history()


def get_scan_stats() -> Dict[str, Any]:
    return _SCAN_HISTORY.get_statistics()


def clear_scan_history():
    _SCAN_HISTORY.clear()
