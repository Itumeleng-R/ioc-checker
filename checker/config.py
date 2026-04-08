"""
config.py — Central configuration for the IOC checker.

Controls which AbuseIPDB backend to use:
  - "local"  → your abuse-api running at localhost:8000
  - "remote" → the real AbuseIPDB at api.abuseipdb.com

Set ABUSEIPDB_MODE in your .env file or as an environment variable.
Defaults to "local" so the project works out of the box without
needing a real AbuseIPDB account.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── AbuseIPDB backend selection ───────────────────────────────────────────────
# "local"  = abuse-api running on localhost (default)
# "remote" = real AbuseIPDB API
ABUSEIPDB_MODE = os.getenv("ABUSEIPDB_MODE", "local").lower()

ABUSEIPDB_ENDPOINTS = {
    "local":  "http://localhost:8000/api/v2",
    "remote": "https://api.abuseipdb.com/api/v2",
}

ABUSEIPDB_BASE_URL = ABUSEIPDB_ENDPOINTS.get(ABUSEIPDB_MODE, ABUSEIPDB_ENDPOINTS["local"])

LOCAL_API_KEY  = os.getenv("LOCAL_API_KEY",  "test-key-123")
REMOTE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Use the right key depending on mode
ABUSEIPDB_API_KEY = LOCAL_API_KEY if ABUSEIPDB_MODE == "local" else REMOTE_API_KEY

# ── VirusTotal ────────────────────────────────────────────────────────────────
VT_API_KEY  = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ── Verdict thresholds ────────────────────────────────────────────────────────
VT_MALICIOUS_THRESHOLD     = 5
VT_SUSPICIOUS_THRESHOLD    = 1
ABUSE_MALICIOUS_THRESHOLD  = 75
ABUSE_SUSPICIOUS_THRESHOLD = 10

# ── Report output ─────────────────────────────────────────────────────────────
REPORT_DIR = "reports"


def print_config() -> None:
    """Print active configuration — useful for debugging."""
    print(f"  AbuseIPDB mode : {ABUSEIPDB_MODE}")
    print(f"  AbuseIPDB URL  : {ABUSEIPDB_BASE_URL}")
    print(f"  VT key set     : {'yes' if VT_API_KEY else 'NO — set VT_API_KEY in .env'}")
    print(f"  AbuseIPDB key  : {'yes' if ABUSEIPDB_API_KEY else 'NO — set key in .env'}")