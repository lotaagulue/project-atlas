from enum import IntEnum
from typing import NamedTuple


class Level(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class LevelMeta(NamedTuple):
    label: str
    color: str  # st.badge color
    emoji: str


META: dict[Level, LevelMeta] = {
    Level.INFO: LevelMeta("INFO", "gray", "⚪"),
    Level.LOW: LevelMeta("LOW", "green", "🟢"),
    Level.MEDIUM: LevelMeta("MEDIUM", "yellow", "🟡"),
    Level.HIGH: LevelMeta("HIGH", "orange", "🟠"),
    Level.CRITICAL: LevelMeta("CRITICAL", "red", "🔴"),
}

_CVSS_SEVERITY = {"CRITICAL": Level.CRITICAL, "HIGH": Level.HIGH, "MEDIUM": Level.MEDIUM, "LOW": Level.LOW}


def score_finding(finding: dict) -> Level:
    """Normalize a stored finding's raw payload into a severity level, based on its source."""
    source = finding.get("source")
    raw = finding.get("raw") or {}

    if source == "ipquery":
        risk = raw.get("risk", {})
        score = risk.get("risk_score") or 0
        if risk.get("is_tor") or risk.get("is_proxy") or score >= 75:
            return Level.HIGH
        if risk.get("is_vpn") or risk.get("is_datacenter") or score > 0:
            return Level.LOW
        return Level.INFO

    if source == "abuseipdb":
        score = raw.get("abuseConfidenceScore") or 0
        if score >= 75:
            return Level.CRITICAL
        if score >= 25:
            return Level.HIGH
        if score > 0:
            return Level.LOW
        return Level.INFO

    if source == "virustotal":
        stats = raw.get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious") or 0
        suspicious = stats.get("suspicious") or 0
        if malicious >= 5:
            return Level.CRITICAL
        if malicious >= 1:
            return Level.HIGH
        if suspicious >= 1:
            return Level.LOW
        return Level.INFO

    if source == "otx":
        count = raw.get("pulse_info", {}).get("count") or 0
        if count >= 10:
            return Level.HIGH
        if count >= 1:
            return Level.MEDIUM
        return Level.INFO

    if source == "nvd":
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = raw.get("metrics", {}).get(key)
            if entries:
                severity = entries[0]["cvssData"].get("baseSeverity", "")
                return _CVSS_SEVERITY.get(severity.upper(), Level.INFO)
        return Level.INFO

    if source == "cisa_kev":
        if raw.get("knownRansomwareCampaignUse") == "Known":
            return Level.CRITICAL
        return Level.HIGH

    return Level.INFO  # unknown/future sources default to a safe, visible-but-unalarming level


def score_target(findings: list[dict]) -> Level:
    """Overall severity for a target: the worst of its individual findings."""
    if not findings:
        return Level.INFO
    return max(score_finding(f) for f in findings)
