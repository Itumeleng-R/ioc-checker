[ioc-checker-README.md](https://github.com/user-attachments/files/26574580/ioc-checker-README.md)
# IOC Reputation Checker

A Python command-line tool that checks Indicators of Compromise (IOCs) —
IP addresses, domains, URLs, and file hashes — against VirusTotal and
AbuseIPDB (or a local AbuseIPDB-compatible API), correlates the results,
and produces colour-coded verdicts with structured JSON reports.

Built as a Tier 1 SOC portfolio project demonstrating threat intelligence
lookup, multi-source correlation, and automated IOC triage.

---

## Demo output

```
[checking] 45.33.32.156  (ipv4)  VT:ok  AB:ok

────────────────────────────────────────────────────────────
[MALICIOUS ]  45.33.32.156  (IPV4)
  Confidence : 85%
  Summary    : VT: 12 malicious, 2 suspicious / 94 engines | AbuseIPDB: 85% (312 reports)

  VirusTotal
    Malicious  : 12
    Suspicious : 2
    Total eng. : 94
    Country    : US
    ASN owner  : Linode LLC (AS63949)
    Flagged by : Kaspersky, ESET, AlienVault, Snort, Emerging Threats

  AbuseIPDB
    Confidence : 85%
    Reports    : 312 (47 sources)
    Last seen  : 2025-03-30T14:22:00
    ISP        : Linode LLC
    Usage type : Data Center/Web Hosting/Transit
```

---

## Features

- Supports 7 IOC types — IPv4, IPv6, domain, URL, MD5, SHA1, SHA256
- Auto-detects IOC type using regex — no manual flags needed
- Queries VirusTotal API v3 and AbuseIPDB v2 simultaneously
- Works with the real AbuseIPDB API or the local abuse-api replacement
- Verdict engine with configurable thresholds — CLEAN / SUSPICIOUS / MALICIOUS
- Composite confidence score (0–100) combining both sources
- Colour-coded console output — green, yellow, bold red
- JSON report saved to `reports/` after every run
- Batch mode — check an entire file of IOCs with one command
- Rate limiting between batch requests to stay within free tier limits

---

## Project structure

```
ioc-checker/
├── checker/
│   ├── __init__.py
│   ├── detector.py       # Regex-based IOC type classifier
│   ├── virustotal.py     # VirusTotal API v3 client
│   ├── abuseipdb.py      # AbuseIPDB v2 client (real or local)
│   ├── correlator.py     # Multi-source verdict engine
│   └── reporter.py       # Console output + JSON report writer
├── reports/              # JSON reports saved here (gitignored)
├── iocs.txt              # Sample batch input — one IOC per line
├── main.py               # CLI entry point
├── requirements.txt
└── .env                  # API keys (never committed)
```

---

## Quickstart

### 1. Install dependencies

```powershell
pip install -r requirements.txt
```

### 2. Add API keys to `.env`

Create a file called `.env` in the project root:

```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

To get free API keys:
- VirusTotal — sign up at virustotal.com → profile → API Key (500 req/day free)
- AbuseIPDB — sign up at abuseipdb.com → Account → API (1,000 req/day free)
- Or use the local abuse-api (see Integration section below)

### 3. Check a single IOC

```powershell
# IP address
python main.py 45.33.32.156

# Domain
python main.py malware.example.com

# URL
python main.py https://suspicious-site.com/payload

# File hash (MD5 / SHA1 / SHA256)
python main.py 44d88612fea8a8f36de82e1278abb02f8ad8d0c8a78b3a46b7f1a6c4c7e1234
```

### 4. Batch check from a file

```powershell
python main.py --batch iocs.txt
```

`iocs.txt` format — one IOC per line, `#` for comments:

```
# Suspicious IPs from last night's alerts
45.33.32.156
203.0.113.99
# Malware hashes
d41d8cd98f00b204e9800998ecf8427e
```

### 5. Control batch rate limiting

```powershell
# Slow down to 2 seconds between requests (safer for free tier)
python main.py --batch iocs.txt --delay 2.0
```

### 6. Skip saving the report

```powershell
python main.py 45.33.32.156 --no-report
```

---

## IOC types supported

| Type | Example | Sources checked |
|------|---------|-----------------|
| IPv4 | `45.33.32.156` | VirusTotal + AbuseIPDB |
| IPv6 | `2001:db8::1` | VirusTotal + AbuseIPDB |
| Domain | `evil.example.com` | VirusTotal only |
| URL | `https://bad.com/mal` | VirusTotal only |
| MD5 hash | `d41d8cd9...` | VirusTotal only |
| SHA1 hash | `da39a3ee...` | VirusTotal only |
| SHA256 hash | `e3b0c442...` | VirusTotal only |

---

## Verdict thresholds

| Condition | Verdict |
|-----------|---------|
| VT malicious engines >= 5 OR AbuseIPDB >= 75% | MALICIOUS |
| VT engines >= 1 OR AbuseIPDB >= 10% OR any reports | SUSPICIOUS |
| No flags from any source | CLEAN |

Thresholds are configurable in `checker/correlator.py`.

---

## JSON report format

```json
{
  "generated_at": "2025-03-30T10:23:01",
  "total_checked": 3,
  "summary": {
    "malicious": 1,
    "suspicious": 1,
    "clean": 1
  },
  "results": [
    {
      "ioc": "45.33.32.156",
      "ioc_type": "ipv4",
      "verdict": "MALICIOUS",
      "confidence": 85,
      "summary": "VT: 12 malicious / 94 engines | AbuseIPDB: 85% (312 reports)",
      "virustotal": { "malicious": 12, "suspicious": 2, ... },
      "abuseipdb":  { "abuse_confidence": 85, "total_reports": 312, ... }
    }
  ]
}
```

---

## Integration with local AbuseIPDB API

If you are running the companion `abuse-api` project locally, switch the
client to point at your local server instead of the real AbuseIPDB:

In `checker/abuseipdb.py`, change:

```python
BASE = "https://api.abuseipdb.com/api/v2"   # real API
# to:
BASE = "http://localhost:8000/api/v2"         # local API
```

In `.env`, change:

```
ABUSEIPDB_API_KEY=test-key-123
```

Start the `abuse-api` server first, then run the IOC checker as normal.
Both tools are designed to work together seamlessly.

---

## MITRE ATT&CK coverage

| Technique | ID | IOC type checked |
|-----------|-----|-----------------|
| Phishing | T1566 | URL, domain |
| Malicious File | T1204 | MD5, SHA1, SHA256 hashes |
| Brute Force | T1110 | IP addresses |
| Active Scanning | T1595 | IP addresses |
| Gather Victim Network Info | T1590 | IP, domain |

---

## Architecture

```
IOC input (string)
    │
    ▼
Detector — classifies type via regex
    │
    ├──▶ VirusTotal client  — queries /ip_addresses /domains /urls /files
    │
    └──▶ AbuseIPDB client   — queries /check (IPs only)
              │
              ▼
         Correlator — combines scores, applies thresholds, sets verdict
              │
              ├──▶ Console reporter — colour-coded terminal output
              │
              └──▶ JSON reporter   — structured report saved to reports/
```

---

## Extending this project

**Feed into the log analyser** — when the log analyser fires a
`BRUTE_FORCE_CRITICAL` alert, automatically pass the source IP into the
IOC checker for instant enrichment. This cross-project integration becomes
your capstone.

**Add Shodan enrichment** — a single `GET https://api.shodan.io/shodan/host/{ip}`
call adds open port data, banners, and CVEs to every IP verdict.

**Add MITRE tagging** — use VirusTotal's `crowdsourced_ids_stats` field to
pull IDS rule matches and map them to ATT&CK technique IDs automatically.

**Add caching** — wrap API calls in a SQLite cache so repeated lookups of
the same IOC within 24 hours return instantly without burning API quota.

---

## Requirements

```
python-dotenv>=1.0.0
```

Python 3.9+. All HTTP calls use Python's built-in `urllib` — no `requests`
library needed. This demonstrates understanding of the underlying HTTP
protocol, which is a strong talking point in interviews.

---

## Scenario

> A SOC analyst receives an alert — a server is being brute-forced from an
> unknown IP. Rather than manually searching VirusTotal and AbuseIPDB in a
> browser, the analyst runs this tool. Within 3 seconds they have a
> MALICIOUS verdict, a confidence score, the ASN owner, flagging vendors,
> and a structured JSON report ready to attach to the incident ticket.

---

## Licence

MIT — use freely for learning, portfolio work, and home lab projects.
