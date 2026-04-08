"""
reporter.py — Console display and JSON report writer.
"""

import json
import os
from datetime import datetime
from typing import List
from .correlator import IOCReport, VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_CLEAN

_COLOURS = {
    VERDICT_MALICIOUS:  "\033[1;31m",   # bold red
    VERDICT_SUSPICIOUS: "\033[33m",     # yellow
    VERDICT_CLEAN:      "\033[32m",     # green
    "UNKNOWN":          "\033[37m",     # grey
}
_RESET = "\033[0m"

_VERDICT_ICON = {
    VERDICT_MALICIOUS:  "[MALICIOUS ]",
    VERDICT_SUSPICIOUS: "[SUSPICIOUS]",
    VERDICT_CLEAN:      "[CLEAN     ]",
    "UNKNOWN":          "[UNKNOWN   ]",
}


def print_report(report: IOCReport) -> None:
    colour = _COLOURS.get(report.verdict, "")
    icon   = _VERDICT_ICON.get(report.verdict, "[?????????]")

    print(f"\n{'─'*60}")
    print(f"{colour}{icon}{_RESET}  {report.ioc}  ({report.ioc_type.upper()})")
    print(f"  Confidence : {report.confidence}%")
    print(f"  Summary    : {report.summary}")

    # VirusTotal detail
    vt = report.vt_result
    if vt and "error" not in vt:
        print(f"\n  VirusTotal")
        print(f"    Malicious  : {vt.get('malicious', 0)}")
        print(f"    Suspicious : {vt.get('suspicious', 0)}")
        print(f"    Harmless   : {vt.get('harmless', 0)}")
        print(f"    Total eng. : {vt.get('total_engines', 0)}")
        if vt.get("country"):
            print(f"    Country    : {vt['country']}")
        if vt.get("as_owner"):
            print(f"    ASN owner  : {vt['as_owner']} (AS{vt.get('asn', '?')})")
        if vt.get("file_name"):
            print(f"    File name  : {vt['file_name']}")
            print(f"    File type  : {vt.get('file_type', '?')}")
        if vt.get("flagged_by"):
            print(f"    Flagged by : {', '.join(vt['flagged_by'][:5])}")
    elif vt and "error" in vt:
        print(f"\n  VirusTotal : ERROR — {vt['error']}")

    # AbuseIPDB detail
    ab = report.abuse_result
    if ab and "error" not in ab:
        print(f"\n  AbuseIPDB")
        print(f"    Confidence : {ab.get('abuse_confidence', 0)}%")
        print(f"    Reports    : {ab.get('total_reports', 0)} ({ab.get('distinct_reporters', 0)} sources)")
        print(f"    Last seen  : {ab.get('last_reported', 'never')}")
        print(f"    ISP        : {ab.get('isp', 'unknown')}")
        print(f"    Usage type : {ab.get('usage_type', 'unknown')}")
        if ab.get("is_tor"):
            print(f"    TOR node   : YES")
    elif ab and "error" in ab:
        print(f"\n  AbuseIPDB : ERROR — {ab['error']}")

    if report.errors:
        print(f"\n  Errors: {'; '.join(report.errors)}")


def print_batch_summary(reports: List[IOCReport]) -> None:
    malicious  = sum(1 for r in reports if r.verdict == VERDICT_MALICIOUS)
    suspicious = sum(1 for r in reports if r.verdict == VERDICT_SUSPICIOUS)
    clean      = sum(1 for r in reports if r.verdict == VERDICT_CLEAN)

    print(f"\n{'='*60}")
    print(f"BATCH SUMMARY — {len(reports)} IOCs checked")
    print(f"{'='*60}")
    print(f"  \033[1;31mMALICIOUS : {malicious}\033[0m")
    print(f"  \033[33mSUSPICIOUS: {suspicious}\033[0m")
    print(f"  \033[32mCLEAN     : {clean}\033[0m")

    if malicious or suspicious:
        print(f"\n  Flagged IOCs:")
        for r in reports:
            if r.verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
                colour = _COLOURS[r.verdict]
                print(f"  {colour}{_VERDICT_ICON[r.verdict]}{_RESET}  {r.ioc}")
    print(f"{'='*60}")


def save_report(reports: List[IOCReport], output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"ioc_report_{ts}.json")

    data = {
        "generated_at": datetime.now().isoformat(),
        "total_checked": len(reports),
        "summary": {
            "malicious":  sum(1 for r in reports if r.verdict == VERDICT_MALICIOUS),
            "suspicious": sum(1 for r in reports if r.verdict == VERDICT_SUSPICIOUS),
            "clean":      sum(1 for r in reports if r.verdict == VERDICT_CLEAN),
        },
        "results": [r.to_dict() for r in reports],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path