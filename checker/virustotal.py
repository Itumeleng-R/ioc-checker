"""
virustotal.py — Query the VirusTotal API v3.
Handles: IPs, domains, URLs, and file hashes.
Docs: https://developers.virustotal.com/reference/overview
"""

import base64
import os
import time
import urllib.request
import urllib.error
import json
from typing import Optional
from .detector import is_ip, is_hash

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VT_API_KEY", "")
        if not self.api_key:
            raise ValueError("VT_API_KEY not set. Add it to your .env file.")

    def lookup(self, ioc: str, ioc_type: str) -> dict:
        """
        Look up any IOC and return a normalised result dict.
        Raises RuntimeError on API failure.
        """
        if is_ip(ioc_type):
            raw = self._get(f"/ip_addresses/{ioc}")
        elif ioc_type == "domain":
            raw = self._get(f"/domains/{ioc}")
        elif ioc_type == "url":
            # URLs must be base64url-encoded (no padding)
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            raw = self._get(f"/urls/{url_id}")
        elif is_hash(ioc_type):
            raw = self._get(f"/files/{ioc}")
        else:
            return {"error": f"Unsupported IOC type for VirusTotal: {ioc_type}"}

        return self._normalise(raw, ioc_type)

    def _get(self, path: str) -> dict:
        url = BASE + path
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "Accept":   "application/json",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(f"VirusTotal HTTP {e.code}: {body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"VirusTotal connection error: {e}")

    def _normalise(self, raw: dict, ioc_type: str) -> dict:
        """Extract the fields we care about into a flat dict."""
        try:
            stats = raw["data"]["attributes"]["last_analysis_stats"]
            malicious   = stats.get("malicious",   0)
            suspicious  = stats.get("suspicious",  0)
            undetected  = stats.get("undetected",  0)
            harmless    = stats.get("harmless",    0)
            total       = malicious + suspicious + undetected + harmless

            # Pull vendor names that flagged as malicious
            engines = raw["data"]["attributes"].get("last_analysis_results", {})
            flagged_by = [
                name for name, result in engines.items()
                if result.get("category") in ("malicious", "suspicious")
            ][:10]  # cap at 10 for readability

            # Extra context fields depending on type
            attrs = raw["data"]["attributes"]
            extra = {}
            if ioc_type in ("ipv4", "ipv6"):
                extra["country"]  = attrs.get("country", "unknown")
                extra["asn"]      = attrs.get("asn", "unknown")
                extra["as_owner"] = attrs.get("as_owner", "unknown")
            if is_hash(ioc_type):
                extra["file_name"] = attrs.get("meaningful_name", "unknown")
                extra["file_type"] = attrs.get("type_description", "unknown")
                extra["file_size"] = attrs.get("size", 0)

            return {
                "source":       "VirusTotal",
                "malicious":    malicious,
                "suspicious":   suspicious,
                "harmless":     harmless,
                "undetected":   undetected,
                "total_engines": total,
                "flagged_by":   flagged_by,
                **extra,
            }

        except (KeyError, TypeError) as e:
            return {"source": "VirusTotal", "error": f"Parse error: {e}", "raw": raw}