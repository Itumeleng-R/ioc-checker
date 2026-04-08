"""
abuseipdb.py — AbuseIPDB v2 client.

Automatically points at either the local abuse-api or the real
AbuseIPDB depending on ABUSEIPDB_MODE in your .env file:

  ABUSEIPDB_MODE=local   → http://localhost:8000/api/v2  (default)
  ABUSEIPDB_MODE=remote  → https://api.abuseipdb.com/api/v2

No other code changes needed when switching modes.
"""

import urllib.request
import urllib.error
import urllib.parse
import json
from typing import Optional

from .config import ABUSEIPDB_BASE_URL, ABUSEIPDB_API_KEY, ABUSEIPDB_MODE


class AbuseIPDBClient:
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = ABUSEIPDB_BASE_URL
        self.api_key  = api_key or ABUSEIPDB_API_KEY

        if not self.api_key:
            raise ValueError(
                "No AbuseIPDB key found.\n"
                "  Local mode:  set LOCAL_API_KEY in .env (default: test-key-123)\n"
                "  Remote mode: set ABUSEIPDB_API_KEY in .env"
            )

    def lookup(self, ip: str, max_age_days: int = 90) -> dict:
        """
        Check an IP address.
        Works identically whether pointing at local abuse-api or real AbuseIPDB.
        """
        params = urllib.parse.urlencode({
            "ipAddress":    ip,
            "maxAgeInDays": max_age_days,
            "verbose":      "",
        })
        url = f"{self.base_url}/check?{params}"
        req = urllib.request.Request(
            url,
            headers={
                "Key":    self.api_key,
                "Accept": "application/json",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = json.loads(resp.read().decode())
                return self._normalise(raw)
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(
                f"AbuseIPDB HTTP {e.code} ({ABUSEIPDB_MODE} mode): {body}"
            )
        except urllib.error.URLError as e:
            if ABUSEIPDB_MODE == "local":
                raise RuntimeError(
                    f"Cannot reach local abuse-api at {self.base_url}.\n"
                    "  Is the server running?  Run this in a separate terminal:\n"
                    "  python -m uvicorn main:app --reload --port 8000"
                )
            raise RuntimeError(f"AbuseIPDB connection error: {e}")

    def _normalise(self, raw: dict) -> dict:
        try:
            d = raw["data"]
            return {
                "source":             "AbuseIPDB",
                "mode":               ABUSEIPDB_MODE,
                "abuse_confidence":   d.get("abuseConfidenceScore", 0),
                "total_reports":      d.get("totalReports",         0),
                "distinct_reporters": d.get("numDistinctUsers",     0),
                "last_reported":      d.get("lastReportedAt",  "never"),
                "country":            d.get("countryCode",    "unknown"),
                "isp":                d.get("isp",            "unknown"),
                "usage_type":         d.get("usageType",      "unknown"),
                "domain":             d.get("domain",         "unknown"),
                "is_tor":             d.get("isTor",              False),
                "is_whitelisted":     d.get("isWhitelisted",      False),
            }
        except (KeyError, TypeError) as e:
            return {"source": "AbuseIPDB", "error": f"Parse error: {e}"}