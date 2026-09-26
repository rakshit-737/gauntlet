"""CTI prioritizer: rank ATT&CK techniques by relevance x prevalence.

Prevalence weights are illustrative, loosely modelled on public technique-frequency
reports (e.g. Red Canary Threat Detection Report). Replace with real data (TODO, Grade C).
"""
from __future__ import annotations

from .models import RankedTechnique, Technique, ThreatProfile

CATALOG: dict[str, Technique] = {t.id: t for t in [
    Technique("T1059.001", "PowerShell", "execution", 0.95, ("sysmon",)),
    Technique("T1003.001", "LSASS Memory", "credential-access", 0.80, ("sysmon",)),
    Technique("T1047", "Windows Management Instrumentation", "execution", 0.60, ("sysmon",)),
    Technique("T1053.005", "Scheduled Task", "persistence", 0.70, ("sysmon", "security")),
    Technique("T1547.001", "Registry Run Keys", "persistence", 0.65, ("sysmon",)),
    Technique("T1021.002", "SMB/Admin Shares", "lateral-movement", 0.55, ("security",)),
    Technique("T1486", "Data Encrypted for Impact", "impact", 0.50, ("sysmon",)),
    Technique("T1490", "Inhibit System Recovery", "impact", 0.55, ("sysmon",)),
    Technique("T1082", "System Information Discovery", "discovery", 0.60, ("sysmon",)),
    Technique("T1071.001", "Web Protocols C2", "command-and-control", 0.75, ("dns", "proxy")),
    Technique("T1566.001", "Spearphishing Attachment", "initial-access", 0.70, ("mail",)),
    Technique("T1110.003", "Password Spraying", "credential-access", 0.45, ("auth",)),
    Technique("T1078", "Valid Accounts", "defense-evasion", 0.65, ("auth",)),
    Technique("T1105", "Ingress Tool Transfer", "command-and-control", 0.70, ("sysmon",)),
]}

PROFILES: dict[str, ThreatProfile] = {
    "ransomware": ThreatProfile(
        "ransomware", "Human-operated ransomware crew targeting mid-size enterprises",
        {"T1059.001": 1.0, "T1003.001": 1.0, "T1047": 0.8, "T1021.002": 0.9, "T1486": 1.0,
         "T1490": 1.0, "T1053.005": 0.6, "T1082": 0.5, "T1105": 0.7, "T1078": 0.7}),
    "espionage": ThreatProfile(
        "espionage", "Long-dwell espionage actor, phishing-led, quiet C2",
        {"T1566.001": 1.0, "T1071.001": 1.0, "T1547.001": 0.9, "T1059.001": 0.8,
         "T1082": 0.7, "T1078": 0.9, "T1003.001": 0.6, "T1105": 0.6}),
    "cloud-credential": ThreatProfile(
        "cloud-credential", "Identity-focused actor abusing credentials",
        {"T1110.003": 1.0, "T1078": 1.0, "T1566.001": 0.6, "T1071.001": 0.4}),
}


def prioritize(profile: ThreatProfile, catalog: dict[str, Technique] | None = None,
               top_n: int | None = None) -> list[RankedTechnique]:
    """Score = relevance x prevalence; ties broken by technique id for determinism."""
    catalog = catalog or CATALOG
    ranked = [RankedTechnique(catalog[tid], round(rel * catalog[tid].prevalence, 4))
              for tid, rel in profile.relevance.items() if tid in catalog and rel > 0]
    ranked.sort(key=lambda r: (-r.score, r.technique.id))
    return ranked[:top_n] if top_n else ranked


def breadth_first(catalog: dict[str, Technique] | None = None) -> list[RankedTechnique]:
    """Baseline ordering (by ID) for the CTI-vs-breadth-first research comparison."""
    catalog = catalog or CATALOG
    return [RankedTechnique(t, 0.0) for t in sorted(catalog.values(), key=lambda t: t.id)]
