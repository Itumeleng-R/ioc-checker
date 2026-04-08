"""
correlator.py — Combine results from multiple sources into a single verdict.

Verdict scale:
  CLEAN       — No engines flagged, abuse confidence < 10
  SUSPICIOUS  — 1-4 VT engines flagged OR abuse confidence 10-74
  MALICIOUS   — 5+ VT engines flagged OR abuse confidence >= 75
"""

from dataclasses import dataclass, field
from typing import Optional


VERDICT_CLEAN      = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_MALICIOUS  = "MALICIOUS"
VERDICT_UNKNOWN    = "UNKNOWN"

# Thresholds — adjust these to tune sensitivity
VT_MALICIOUS_THRESHOLD   = 5    # engines flagging as malicious → MALICIOUS
VT_SUSPICIOUS_THRESHOLD  = 1    # engines flagging → at least SUSPICIOUS
ABUSE_MALICIOUS_THRESHOLD   = 75  # confidence score → MALICIOUS
ABUSE_SUSPICIOUS_THRESHOLD  = 10  # confidence score → SUSPICIOUS


@dataclass
class IOCReport:
    ioc:         str
    ioc_type:    str
    verdict:     str = VERDICT_UNKNOWN
    confidence:  int = 0          # 0-100 composite confidence score
    vt_result:   Optional[dict] = None
    abuse_result: Optional[dict] = None
    errors:      list = field(default_factory=list)
    summary:     str  = ""

    def to_dict(self) -> dict:
        return {
            "ioc":          self.ioc,
            "ioc_type":     self.ioc_type,
            "verdict":      self.verdict,
            "confidence":   self.confidence,
            "summary":      self.summary,
            "virustotal":   self.vt_result,
            "abuseipdb":    self.abuse_result,
            "errors":       self.errors,
        }


def correlate(
    ioc: str,
    ioc_type: str,
    vt_result: Optional[dict],
    abuse_result: Optional[dict],
) -> IOCReport:
    """
    Combine VirusTotal and AbuseIPDB results into a single IOCReport.
    """
    report = IOCReport(ioc=ioc, ioc_type=ioc_type)
    report.vt_result    = vt_result
    report.abuse_result = abuse_result

    if vt_result and "error" in vt_result:
        report.errors.append(f"VirusTotal: {vt_result['error']}")
    if abuse_result and "error" in abuse_result:
        report.errors.append(f"AbuseIPDB: {abuse_result['error']}")

    # ── Score from VirusTotal ─────────────────────────────────────────────────
    vt_malicious   = vt_result.get("malicious",  0)   if vt_result  else 0
    vt_suspicious  = vt_result.get("suspicious", 0)   if vt_result  else 0
    vt_total       = vt_result.get("total_engines", 1) if vt_result else 1
    vt_hits = vt_malicious + vt_suspicious

    # ── Score from AbuseIPDB ──────────────────────────────────────────────────
    abuse_score    = abuse_result.get("abuse_confidence", 0) if abuse_result else 0
    abuse_reports  = abuse_result.get("total_reports",    0) if abuse_result else 0
    is_tor         = abuse_result.get("is_tor",          False) if abuse_result else False

    # ── Determine verdict ─────────────────────────────────────────────────────
    is_malicious = (
        vt_malicious  >= VT_MALICIOUS_THRESHOLD or
        abuse_score   >= ABUSE_MALICIOUS_THRESHOLD or
        is_tor
    )
    is_suspicious = (
        vt_hits       >= VT_SUSPICIOUS_THRESHOLD or
        abuse_score   >= ABUSE_SUSPICIOUS_THRESHOLD or
        abuse_reports > 0
    )

    if is_malicious:
        report.verdict = VERDICT_MALICIOUS
    elif is_suspicious:
        report.verdict = VERDICT_SUSPICIOUS
    else:
        report.verdict = VERDICT_CLEAN

    # ── Composite confidence score (0-100) ────────────────────────────────────
    vt_confidence    = int((vt_hits / max(vt_total, 1)) * 100)
    composite        = max(vt_confidence, abuse_score)
    if is_tor:
        composite    = max(composite, 80)
    report.confidence = composite

    # ── Human-readable summary ────────────────────────────────────────────────
    parts = []
    if vt_result and "error" not in vt_result:
        parts.append(f"VT: {vt_malicious} malicious, {vt_suspicious} suspicious / {vt_total} engines")
    if abuse_result and "error" not in abuse_result:
        parts.append(f"AbuseIPDB: {abuse_score}% confidence ({abuse_reports} reports)")
    if is_tor:
        parts.append("TOR exit node detected")
    report.summary = " | ".join(parts) if parts else "No data available"

    return report