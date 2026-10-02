import time

from gauntlet import formats
from gauntlet.replay import RuleIndex
from gauntlet.sigma import parse_rule

# Synthetic auditd group: whoami, argv hex-encoded the way the kernel writes non-ASCII-safe args.
AUDIT = [
    'type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 '
    'ppid=100 pid=101 auid=1001 uid=1001 comm="whoami" exe="/usr/bin/whoami" key="gauntlet_exec"',
    'type=EXECVE msg=audit(1700000000.123:42): argc=1 a0="whoami"',
    'type=CWD msg=audit(1700000000.123:42): cwd="/tmp"',
    'type=SYSCALL msg=audit(1700000001.000:43): syscall=59 ppid=100 pid=102 exe="/usr/bin/uname" key="k"',
    'type=EXECVE msg=audit(1700000001.000:43): argc=2 a0="uname" a1=2D61',
]

XML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
       "<EventID>1</EventID><TimeCreated SystemTime='2024-01-01T00:00:00Z'/>"
       "<Channel>Linux-Sysmon/Operational</Channel><Computer>h</Computer></System><EventData>"
       "<Data Name='Image'>/usr/bin/id</Data><Data Name='CommandLine'>id &amp;&amp; x</Data>"
       "<Data Name='Empty'/></EventData></Event>")


def test_kv_regex_handles_escaped_quotes():
    assert formats._KV.findall('a2="x \\" y" b=3') == [("a2", '"x \\" y"'), ("b", "3")]


def test_parse_audit_line_and_hex():
    ev = formats.parse_audit_line(AUDIT[4])
    assert ev["type"] == "EXECVE" and ev["a1"] == "-a" and ev["serial"] == 43


def test_audit_exec_events():
    recs = [formats.parse_audit_line(x) for x in AUDIT]
    out = list(formats.audit_exec_events(recs))
    assert [e["Image"] for e in out] == ["/usr/bin/whoami", "/usr/bin/uname"]
    assert out[0]["CurrentDirectory"] == "/tmp" and out[1]["CommandLine"] == "uname -a"
    assert out[0]["ParentProcessId"] == "100"


def test_parse_xml_event():
    ev = formats.parse_xml_event(XML)
    assert ev["EventID"] == "1" and ev["Channel"] == "Linux-Sysmon/Operational"
    assert ev["CommandLine"] == "id && x" and ev["Empty"] == ""


def test_iter_text_lines_sniffs_and_strips_bom():
    evs = list(formats.iter_text_lines(["﻿{\"a\": 1}", XML, *AUDIT, ""]))
    assert evs[0] == {"a": 1}
    assert sum(e.get("Channel") == "auditd-exec" for e in evs) == 2


def test_linux_rule_fires_on_auditd_exec():
    r = parse_rule({"title": "w", "id": "w1", "logsource": {"product": "linux", "category": "process_creation"},
                    "detection": {"sel": {"Image|endswith": "/whoami"}, "condition": "sel"},
                    "tags": ["attack.t1033"]})
    _, _, hits = RuleIndex([r]).evaluate(formats.iter_text_lines(AUDIT))
    assert hits == {"w1": {"auditd-exec": 1}}


def test_pathological_inputs_are_fast():
    t = time.perf_counter()
    formats.parse_xml_event("<Event>" + "<Data Name='x'>" * 20000)
    formats.parse_xml_event("<Event>" + "<EventID" * 20000)
    recs = [formats.parse_audit_line('type=EXECVE msg=audit(1.0:1): argc=5000000 a0="x"')]
    out = list(formats.audit_exec_events(recs))
    assert out[0]["CommandLine"] == "x"
    assert time.perf_counter() - t < 2.0
