import base64

import pytest

from gauntlet import sigma
from gauntlet.sigma import SYSMON, EventView, UnsupportedRule, parse_rule

PROC = {"product": "windows", "category": "process_creation"}


def rule(detection, logsource=PROC, **kw):
    return parse_rule({"title": "t", "id": "r1", "logsource": logsource, "detection": detection,
                       "tags": ["attack.execution", "attack.t1059.001"], **kw})


def ev(**fields):
    return EventView(fields)


def test_tags_and_targets():
    r = rule({"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"})
    assert r.techniques == ("T1059.001",)
    assert r.tactics == ("execution",)
    assert (SYSMON, 1) in r.targets and ("security", 4688) in r.targets


@pytest.mark.parametrize("key,val,field,ok", [
    ("Image|endswith", "\\cmd.exe", "C:\\Windows\\System32\\CMD.EXE", True),
    ("Image|startswith", "c:\\windows\\", "C:\\Windows\\x.exe", True),
    ("CommandLine|contains", "-nop", "powershell -EncodedCommand", False),
    ("CommandLine|contains", "-Enc", "powershell -EncodedCommand", True),
    ("Image", "*\\rundll32.exe", "C:\\Windows\\rundll32.exe", True),
    ("Image", "C:\\Win?ows\\a.exe", "c:\\windows\\a.exe", True),
    ("Image", "a.exe", "b.exe", False),
    ("CommandLine|re", "-[eE]nc\\s", "x -enc abc", True),
    ("CommandLine|re", "-ENC", "x -enc abc", False),       # re is case-sensitive
    ("CommandLine|re|i", "-ENC", "x -enc abc", True),
    ("CommandLine|windash|contains", "-urlcache", "certutil /urlcache -f", True),
    ("CommandLine|cased|contains", "Invoke", "invoke-x", False),
    ("DestinationIp|cidr", "10.0.0.0/8", "10.1.2.3", True),
    ("DestinationIp|cidr", "10.0.0.0/8", "192.168.1.1", False),
    ("DestinationPort|gte", 1024, "4444", True),
    ("DestinationPort|lt", 1024, "4444", False),
])
def test_modifiers(key, val, field, ok):
    name = key.split("|")[0]
    r = rule({"sel": {key: val}, "condition": "sel"})
    assert r.match(ev(**{name: field})) is ok


def test_all_modifier_and_lists():
    r = rule({"sel": {"CommandLine|contains|all": ["vssadmin", "delete", "shadows"]}, "condition": "sel"})
    assert r.match(ev(CommandLine="vssadmin.exe Delete Shadows /all"))
    assert not r.match(ev(CommandLine="vssadmin.exe list shadows"))
    r2 = rule({"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "sel"})
    assert r2.match(ev(Image="C:\\b.exe")) and not r2.match(ev(Image="C:\\c.exe"))


def test_base64offset_contains():
    payload = "IEX (New-Object Net.WebClient)"
    enc = base64.b64encode(b"xx" + payload.encode()).decode()
    r = rule({"sel": {"CommandLine|base64offset|contains": "IEX (New-Object"}, "condition": "sel"})
    assert r.match(ev(CommandLine=f"powershell -e {enc}"))


def test_utf16_base64offset():
    enc = base64.b64encode("Invoke-Mimikatz".encode("utf-16-le")).decode()
    r = rule({"sel": {"CommandLine|wide|base64offset|contains": "Invoke-Mimikatz"}, "condition": "sel"})
    assert r.match(ev(CommandLine=f"powershell -enc {enc}"))


def test_null_and_exists():
    r = rule({"sel": {"Image|endswith": "\\x.exe"}, "f": {"OriginalFileName": None}, "condition": "sel and f"})
    assert r.match(ev(Image="C:\\x.exe"))
    assert not r.match(ev(Image="C:\\x.exe", OriginalFileName="x.exe"))
    r2 = rule({"sel": {"Hashes|exists": True}, "condition": "sel"})
    assert r2.match(ev(Hashes="MD5=1")) and not r2.match(ev(Image="a"))


def test_keywords_and_list_of_maps():
    r = rule({"kw": ["mimikatz", "sekurlsa::*"], "condition": "kw"},
             logsource={"product": "windows", "service": "security"})
    assert r.match(ev(Message="ran SEKURLSA::logonpasswords"))
    assert not r.match(ev(Message="nothing here"))
    r2 = rule({"sel": [{"Image|endswith": "\\a.exe"}, {"CommandLine|contains": "zzz"}], "condition": "sel"})
    assert r2.match(ev(Image="c:\\a.exe")) and r2.match(ev(CommandLine="xzzzx"))


def test_condition_grammar():
    d = {"selection_a": {"Image|endswith": "\\a.exe"}, "selection_b": {"CommandLine|contains": "b"},
         "filter_main": {"User": "SYSTEM"}}
    one = rule({**d, "condition": "1 of selection_* and not filter_main"})
    allof = rule({**d, "condition": "all of selection_*"})
    paren = rule({**d, "condition": "(selection_a or selection_b) and not 1 of filter_*"})
    them = rule({**d, "condition": "1 of them"})
    e1 = ev(Image="c:\\a.exe", CommandLine="zzz", User="bob")
    e2 = ev(Image="c:\\a.exe", CommandLine="b", User="SYSTEM")
    assert one.match(e1) and not one.match(e2)
    assert not allof.match(e1) and allof.match(e2)
    assert paren.match(e1) and not paren.match(e2)
    assert them.match(ev(User="system"))


def test_condition_list_is_or():
    r = rule({"a": {"X": "1"}, "b": {"Y": "2"}, "condition": ["a", "b"]})
    assert r.match(ev(Y="2"))


@pytest.mark.parametrize("det,ls", [
    ({"sel": {"a": 1}, "condition": "sel | count() by b > 5"}, PROC),
    ({"sel": {"a|expand": "%x%"}, "condition": "sel"}, PROC),
    ({"sel": {"a": 1}, "condition": "sel"}, {"product": "linux", "category": "process_creation"}),
    ({"sel": {"a": 1}, "condition": "sel"}, {"product": "windows", "category": "no_such_cat"}),
    ({"sel": {"a": 1}, "condition": "nope"}, PROC),
])
def test_unsupported(det, ls):
    with pytest.raises(UnsupportedRule):
        rule(det, logsource=ls)


def test_security_4688_field_mapping():
    r = rule({"sel": {"Image|endswith": "\\whoami.exe", "ParentImage|endswith": "\\cmd.exe"}, "condition": "sel"})
    raw = {"NewProcessName": "C:\\Windows\\System32\\whoami.exe", "ParentProcessName": "C:\\Windows\\cmd.exe"}
    assert not r.match(EventView(raw))
    assert r.match(EventView(raw, sigma.SECURITY_4688_MAP))


def test_load_rules_from_texts_collects_unsupported():
    good = """
title: ok
id: 1
logsource: {product: windows, category: process_creation}
detection: {sel: {Image|endswith: '\\\\a.exe'}, condition: sel}
tags: [attack.t1059]
"""
    bad = "title: bad\nlogsource: {product: linux}\ndetection: {sel: {a: 1}, condition: sel}\n"
    rs = sigma.load_rules_from_texts([("a.yml", good), ("b.yml", bad), ("c.yml", ":\n  - [")])
    assert [r.title for r in rs.rules] == ["ok"]
    assert set(rs.unsupported) == {"b.yml", "c.yml"}


def test_rule_cites_references():
    r = rule({"sel": {"a": 1}, "condition": "sel"},
             references=["https://securitydatasets.com/notebooks/x.html"], description="d")
    assert r.cites("securitydatasets|mordor") and not r.cites("unrelated")
