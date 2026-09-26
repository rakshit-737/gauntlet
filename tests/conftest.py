import json
import zipfile
from pathlib import Path

import pytest

from gauntlet import paths


def _ap(tid, name, tactic):
    return {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            "x_mitre_platforms": ["Windows"]}


def _grp(gid, name, desc):
    return {"type": "intrusion-set", "id": f"intrusion-set--{gid}", "name": name, "aliases": [name, name + "X"],
            "description": desc, "external_references": [{"source_name": "mitre-attack", "external_id": gid}]}


def _uses(src, dst):
    return {"type": "relationship", "relationship_type": "uses", "source_ref": src, "target_ref": dst,
            "id": f"relationship--{src}-{dst}"}


TECHS = [("T1059", "Command and Scripting Interpreter", "execution"),
         ("T1059.001", "PowerShell", "execution"),
         ("T1003", "OS Credential Dumping", "credential-access"),
         ("T1003.001", "LSASS Memory", "credential-access"),
         ("T1486", "Data Encrypted for Impact", "impact"),
         ("T1490", "Inhibit System Recovery", "impact"),
         ("T1566.001", "Spearphishing Attachment", "initial-access"),
         ("T1082", "System Information Discovery", "discovery")]


def mini_bundle() -> dict:
    objs = [_ap(*t) for t in TECHS]
    objs.append({**_ap("T9999", "Old", "impact"), "revoked": True})
    objs += [
        _grp("G0001", "RansomA", "A financially motivated ransomware group."),
        _grp("G0002", "RansomB", "Deploys ransomware against hospitals."),
        _grp("G0003", "SpyC", "A cyber espionage group."),
        {"type": "malware", "id": "malware--S0001", "name": "Lockr",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "x_mitre_shortname": "initial-access"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "x_mitre_shortname": "execution"},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": ["x-mitre-tactic--1", "x-mitre-tactic--2"]},
    ]
    uses = {"G0001": ["T1059.001", "T1003.001", "T1486"], "G0002": ["T1059.001", "T1490"],
            "G0003": ["T1566.001", "T1059.001", "T1082"]}
    for g, ts in uses.items():
        objs += [_uses(f"intrusion-set--{g}", f"attack-pattern--{t}") for t in ts]
    objs.append(_uses("malware--S0001", "attack-pattern--T1486"))
    objs.append(_uses("intrusion-set--G0002", "malware--S0001"))
    return {"type": "bundle", "objects": objs}


@pytest.fixture
def mini_kb():
    from gauntlet.attack import parse_stix
    return parse_stix(mini_bundle(), "19.2")


SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _write_dataset(root: Path, sdid: str, tech: str, sub, events: list[dict], tactic="credential_access"):
    name = f"{sdid.lower()}.zip"
    host = root / "mordor" / "windows" / tactic / "host"
    host.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(host / name, "w") as z:
        z.writestr(f"{sdid}.json", "\n".join(json.dumps(e) for e in events))
    meta = root / "mordor" / "_metadata"
    meta.mkdir(parents=True, exist_ok=True)
    link = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/{tactic}/host/{name}"
    sub_line = f'    sub-technique: "{sub}"\n' if sub else ""
    (meta / f"{sdid}.yaml").write_text(
        f"title: {sdid}\nid: {sdid}\nattack_mappings:\n  - technique: {tech}\n{sub_line}"
        f"files:\n  - type: Host\n    link: {link}\n  - type: Network\n    link: https://x.invalid/n.zip\n",
        encoding="utf-8")


LSASS_EVENT = {"Channel": SYSMON, "EventID": 10, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
               "SourceImage": "C:\\Users\\Public\\dump.exe", "GrantedAccess": "0x1010"}
VSS_EVENT = {"Channel": "Security", "EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
             "CommandLine": "vssadmin.exe delete shadows /all /quiet",
             "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"}
NOISE = [{"Channel": SYSMON, "EventID": 1, "Image": "C:\\Windows\\System32\\whoami.exe",
          "CommandLine": "whoami /all", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},
         {"Channel": "Security", "EventID": 4624, "TargetUserName": "alice"}]

SIGMA_RULES = {
    "lsass.yml": """
title: LSASS access from user dir
id: r-lsass
status: test
level: high
tags: [attack.credential-access, attack.t1003.001]
logsource: {product: windows, category: process_access}
detection:
  selection: {TargetImage|endswith: '\\\\lsass.exe', GrantedAccess: ['0x1010', '0x1410']}
  filter_main: {SourceImage|startswith: 'C:\\\\Windows\\\\System32\\\\'}
  condition: selection and not 1 of filter_*
""",
    "vss.yml": """
title: Shadow copies deleted
id: r-vss
status: stable
level: critical
tags: [attack.impact, attack.t1490]
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\\\\vssadmin.exe', CommandLine|contains|all: [delete, shadows]}
  condition: selection
""",
    "whoami.yml": """
title: Whoami execution
id: r-whoami
status: test
level: medium
tags: [attack.discovery, attack.t1033]
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\\\\whoami.exe'}
  condition: selection
""",
}


@pytest.fixture
def mini_data(tmp_path):
    """A tiny Mordor-style data dir: 3 recordings + a Sigma rule directory."""
    _write_dataset(tmp_path, "SDWIN-1", "T1003", "001", [LSASS_EVENT, *NOISE])
    _write_dataset(tmp_path, "SDWIN-2", "T1490", None, [VSS_EVENT, *NOISE], tactic="impact")
    _write_dataset(tmp_path, "SDWIN-3", "T1082", None, NOISE, tactic="discovery")
    rdir = tmp_path / "sigma_rules"
    rdir.mkdir()
    for n, t in SIGMA_RULES.items():
        (rdir / n).write_text(t, encoding="utf-8")
    return tmp_path


def has_real_data() -> bool:
    return paths.have_real_data()
