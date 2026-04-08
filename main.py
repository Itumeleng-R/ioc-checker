"""
main.py — IOC Reputation Checker entry point.

Usage:
  python main.py 45.33.32.156                         # single IP
  python main.py malware.example.com                   # single domain
  python main.py d41d8cd98f00b204e9800998ecf8427e      # MD5 hash
  python main.py --batch iocs.txt                      # batch from file
  python main.py 45.33.32.156 --no-report              # skip saving JSON
"""

import argparse
import os
import sys
import time

from dotenv import load_dotenv

from checker.detector   import detect
from checker.virustotal import VirusTotalClient
from checker.abuseipdb  import AbuseIPDBClient
from checker.correlator import correlate
from checker.reporter   import print_report, print_batch_summary, save_report
from checker            import __init__

load_dotenv()   # load .env file into environment


def check_ioc(ioc: str, vt: VirusTotalClient, ab: AbuseIPDBClient) -> object:
    """Run a single IOC through all available sources."""
    ioc       = ioc.strip()
    ioc_type  = detect(ioc)

    if ioc_type == "unknown":
        print(f"[skip] Could not classify IOC: {ioc}")
        return None

    print(f"[checking] {ioc}  ({ioc_type})", end="", flush=True)

    # ── VirusTotal (all types) ────────────────────────────────────────────────
    vt_result = None
    try:
        vt_result = vt.lookup(ioc, ioc_type)
        print("  VT:ok", end="", flush=True)
    except RuntimeError as e:
        vt_result = {"error": str(e)}
        print(f"  VT:err", end="", flush=True)

    # ── AbuseIPDB (IPs only) ──────────────────────────────────────────────────
    ab_result = None
    if ioc_type in ("ipv4", "ipv6"):
        try:
            ab_result = ab.lookup(ioc)
            print("  AB:ok", end="", flush=True)
        except RuntimeError as e:
            ab_result = {"error": str(e)}
            print(f"  AB:err", end="", flush=True)

    print()  # newline after status ticks

    return correlate(ioc, ioc_type, vt_result, ab_result)


def load_batch(path: str) -> list:
    """Read IOCs from a file — one per line, ignoring blank lines and # comments."""
    with open(path, "r") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(description="IOC Reputation Checker")
    parser.add_argument("ioc", nargs="?", help="Single IOC to check")
    parser.add_argument("--batch", metavar="FILE",
                        help="Path to a file with one IOC per line")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip saving JSON report")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to wait between API calls in batch mode (default: 1.0)")
    args = parser.parse_args()

    if not args.ioc and not args.batch:
        parser.print_help()
        sys.exit(1)

    # Initialise clients
    try:
        vt = VirusTotalClient()
        ab = AbuseIPDBClient()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    reports = []

    if args.batch:
        iocs = load_batch(args.batch)
        print(f"Loaded {len(iocs)} IOCs from {args.batch}\n")
        for i, ioc in enumerate(iocs):
            report = check_ioc(ioc, vt, ab)
            if report:
                print_report(report)
                reports.append(report)
            # Rate-limit between requests to stay within free tier limits
            if i < len(iocs) - 1:
                time.sleep(args.delay)
        print_batch_summary(reports)
    else:
        report = check_ioc(args.ioc, vt, ab)
        if report:
            print_report(report)
            reports.append(report)

    if reports and not args.no_report:
        path = save_report(reports)
        print(f"\nReport saved → {path}")


if __name__ == "__main__":
    main()