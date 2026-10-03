import importlib.util
import json
from pathlib import Path

import pytest

from gauntlet import extended, live, mordor, stats
from gauntlet.replay import ReplayResult
from gauntlet.sigma import parse_rule

REPO = Path(__file__).resolve().parent.parent


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lrule(rid, tag, sel):
    return parse_rule({"title": rid, "id": rid, "tags": [f"attack.{tag.lower()}"],
                       "logsource": {"product": "linux", "category": "process_creation"},
                       "detection": {"sel": sel, "condition": "sel"}})


AUDIT = """type=SYSCALL msg=audit(1.000:10): syscall=59 ppid=1 pid=500 exe="/usr/bin/whoami" key="g"
type=EXECVE msg=audit(1.000:10): argc=1 a0="whoami"
type=SYSCALL msg=audit(2.000:11): syscall=59 ppid=1 pid=501 exe="/usr/bin/uname" key="g"
type=EXECVE msg=audit(2.000:11): argc=2 a0="uname" a1="-a"
type=SYSCALL msg=audit(3.000:12): syscall=59 ppid=1 pid=900 exe="/usr/bin/apt" key="g"
type=EXECVE msg=audit(3.000:12): argc=1 a0="apt"
"""


def test_live_score_event_level(tmp_path):
    (tmp_path / "a.log").write_text(AUDIT)
    (tmp_path / "l.json").write_text(json.dumps({"commands": [
        {"argv": ["whoami"], "technique": "T1033", "pid": 500},
        {"argv": ["uname", "-a"], "technique": "T1082", "pid": 501}]}))
    rules = [lrule("who", "T1033", {"Image|endswith": "/whoami"}),
             lrule("apt", "T1059", {"Image|endswith": "/apt"})]
    r = live.score(tmp_path / "a.log", tmp_path / "l.json", rules)
    assert r["labelled_events"] == 6 and r["background_events"] == 3
    assert r["techniques"] == {"T1033": {"claimed": True, "measured": True},
                               "T1082": {"claimed": False, "measured": False}}
    assert r["background_rules_fired"] == ["apt"]
    md = live.render_md({"rulesets": {"x": r}, "replayed": {"x": {"T1033": False}}})
    assert "`whoami` | T1033" in md


def test_claimed_vs_measured_and_gaps():
    rules = {r.id: r for r in [lrule("a", "T1033", {"Image|endswith": "/whoami"}),
                               lrule("b", "T1082", {"Image|endswith": "/uname"})]}
    res = [ReplayResult("d1", ("T1033",), 5, {"auditd-exec": 5}, {"a": {"auditd-exec": 1}}, {"auditd-exec|1": 5}),
           ReplayResult("d2", ("T1082",), 5, {"auditd-exec": 5}, {}, {"auditd-exec|1": 5}),
           ReplayResult("d3", ("T1082.001",), 5, {"auditd": 5}, {}, {"auditd|None": 5}),
           # right channel, wrong event type: the rule could not fire -> telemetry gap, not rule logic
           ReplayResult("d4", ("T1082.002",), 5, {"linux-sysmon/operational": 5}, {},
                        {"linux-sysmon/operational|3": 5})]
    out = extended.claimed_vs_measured(res, rules)
    assert out["claimed"] == 4 and out["measured"] == 1
    gaps = {r["technique"]: r["gap"] for r in out["rows"]}
    assert gaps == {"T1033": None, "T1082": "rule_logic_gap", "T1082.001": "telemetry_gap",
                    "T1082.002": "telemetry_gap"}
    # nested comparison: reported as an interval on claimed-only / techniques, not a McNemar test
    assert out["discordant_measured_only"] == 0 and "mcnemar_p" not in out
    assert out["overstatement_points"] == 75.0 and stats.fmt_ci(out["overstatement_ci95"]) == " [30.1, 95.4]"
    assert out["exact_id"]["claimed"] == 2 and out["exact_id"]["measured"] == 1


def test_exact_tests():
    assert stats.mcnemar_exact(10, 0) == pytest.approx(2 * 0.5 ** 10)
    assert stats.binom_two_sided(0, 4) == 0.125
    assert stats.mcnemar_exact(0, 0) == 1.0


def test_splunk_and_compound_loaders(tmp_path):
    man = {"recordings": [{"id": "SPLK-1", "title": "t", "techniques": ["T1033"],
                           "files": [{"path": "datasets/attack_techniques/T1033/x/a.log", "sourcetype": "auditd"}]},
                          {"id": "SPLK-2", "title": "w", "techniques": ["T1003.001"],
                           "files": [{"path": "datasets/attack_techniques/T1003.001/y/b.log",
                                      "sourcetype": "XmlWinEventLog"}]},
                          {"id": "SPLK-3", "title": "mixed", "techniques": ["T1082"],
                           "files": [{"path": "datasets/attack_techniques/T1082/z/l.log", "sourcetype": "sysmon:linux"},
                                     {"path": "datasets/attack_techniques/T1082/z/w.log",
                                      "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}]}]}
    mp = tmp_path / "m.json"
    mp.write_text(json.dumps(man))
    ds = mordor.load_splunk(tmp_path, mp)
    # files are routed by sourcetype: a mixed recording is scored with both platforms' rules
    assert [(d.id, d.tactic_dir, d.source, [f.name for f in d.files]) for d in ds] == [
        ("SPLK-1", "linux", "splunk", ["a.log"]), ("SPLK-2", "windows", "splunk", ["b.log"]),
        ("SPLK-3@linux", "linux", "splunk", ["l.log"]), ("SPLK-3@windows", "windows", "splunk", ["w.log"])]
    assert mordor.splunk_sourcetypes(mp)["attack_techniques/T1082/z/l.log"] == "sysmon:linux"
    md = tmp_path / "mordor-compound" / "_metadata"
    md.mkdir(parents=True)
    (md / "LSASS_campaign_01.yaml").write_text(
        "id: CMP-1\ntitle: c\nattack_mappings:\n- technique: T1003\n  sub-technique: '001'\n"
        "files:\n- type: Host\n  link: https://x/master/datasets/compound/LSASS_campaign_01/a.zip\n")
    c = mordor.load_compound(tmp_path)
    assert c[0].techniques == ("T1003.001",) and c[0].files[0].name == "a.zip"


def test_committed_splunk_manifest_paths_are_safe():
    man = json.loads((REPO / "scripts" / "splunk_attack_data.json").read_text(encoding="utf-8"))
    assert man["recordings"]
    for r in man["recordings"]:
        for f in r["files"]:
            assert f["path"].startswith("datasets/attack_techniques/") and ".." not in f["path"].split("/")
            assert len(f["sha256"]) == 64 and f["size"] <= man["max_bytes"]


def test_live_allowlist_is_benign():
    em = _load_script("live_emulate")
    em.check_allowlist()
    bins = {Path(argv[0]).name for argv, _ in em.ALLOWLIST}
    assert bins <= {"whoami", "id", "uname", "hostname", "cat", "ps", "crontab", "ls"}
    assert ("crontab", "-l") in {a for a, _ in em.ALLOWLIST}
    assert em.main("x.json") == 3 or __import__("os").environ.get("GITHUB_ACTIONS") == "true"


def test_fetcher_refuses_path_escape(tmp_path):
    dl = _load_script("download_data")
    f = dl.Fetcher(tmp_path, {})
    with pytest.raises(ValueError):
        f.fetch("https://example.invalid/x", "../evil.txt")


def test_fetcher_records_av_blocked_part_and_continues(tmp_path, monkeypatch):
    dl = _load_script("download_data")
    payload = b"recorded events"

    def fake_stream(url, dest):
        dest.write_bytes(payload)

    real = dl._sha256

    def fake_sha(p, retries=10):
        if str(p).endswith(".part") and "blocked" in str(p):
            raise OSError(22, "Invalid argument")  # what Defender produces on Windows
        return real(p, retries)

    monkeypatch.setattr(dl, "_stream", fake_stream)
    monkeypatch.setattr(dl, "_sha256", fake_sha)
    import hashlib

    digest = hashlib.sha256(payload).hexdigest()
    f = dl.Fetcher(tmp_path, {"mordor/blocked.zip": digest, "mordor/ok.zip": digest})
    f.fetch("https://example.invalid/a", "mordor/blocked.zip")
    f.fetch("https://example.invalid/b", "mordor/ok.zip")  # later sources are still fetched
    assert f.unreadable == ["mordor/blocked.zip"] and not f.bad
    assert (tmp_path / "mordor" / "ok.zip").read_bytes() == payload
    assert not (tmp_path / "mordor" / "blocked.zip.part").exists()
    assert json.loads((tmp_path / ".av-skipped.json").read_text()) == ["mordor/blocked.zip"]
    g = dl.Fetcher(tmp_path, {})  # a re-run does not fetch it again
    monkeypatch.setattr(dl, "_stream", lambda *a: pytest.fail("re-fetched a skipped file"))
    g.fetch("https://example.invalid/a", "mordor/blocked.zip")


def test_published_comparisons():
    from gauntlet import published

    ctid = [{"tid": "T1003", "has_sigma": True}, {"tid": "T1012", "has_sigma": True},
            {"tid": "T1135", "has_sigma": False}]
    rows = [{"technique": "T1003.001", "outcome": "detected"}, {"technique": "T1012", "outcome": "missed"},
            {"technique": "T1135", "outcome": "partial"}, {"technique": "T9999", "outcome": "missed"}]
    c = published.ctid_vs_measured(ctid, rows)
    assert c["techniques_compared"] == 3 and c["claimed_not_measured"] == ["T1012"]
    assert c["measured_not_claimed"] == ["T1135"]
    rg = {"summary": {"techniques": 2, "detected": 1},
          "techniques": [{"id": "T1033", "name": "x", "detected": False, "gap_type": "rule"},
                         {"id": "T1082", "name": "y", "detected": True, "gap_type": "none"}]}
    live_rep = {"rulesets": {"sigma-full": {"techniques": {"T1033": {"measured": True}}}}}
    r = published.redgap_vs_live(rg, live_rep, [{"technique": "T1082", "measured": False}])
    assert [(x["technique"], x["gauntlet_live"], x["gauntlet_splunk_replay"]) for x in r["rows"]] == [
        ("T1033", {"sigma-full": True}, None), ("T1082", None, False)]
    assert "reports 1/2 techniques detected" in published.render_md({"ctid": c, "redgap": r})


def test_held_out_selection_runs():
    from gauntlet.attack import load_kb

    rules = {r.id: r for r in [lrule("a", "T1033", {"Image": "x"}), lrule("b", "T1082", {"Image": "y"})]}
    tr = [ReplayResult("d1", ("T1033",), 1, {}, {"a": {"c": 1}}),
          ReplayResult("d2", ("T1082",), 1, {}, {"b": {"c": 1}})]
    te = [ReplayResult("e1", ("T1033",), 1, {}, {"a": {"c": 1}}), ReplayResult("e2", ("T1082",), 1, {}, {})]
    out = extended.held_out_selection((tr, rules), (te, rules), load_kb(), k=1, seeds=10)
    assert out["candidate_rules"] == 2
    assert out["greedy_unweighted"]["test_technique_coverage"] in (0.0, 0.5)
    assert 0.0 <= out["random"]["test_technique_coverage_mean"] <= 0.5


def test_manifest_out_creates_missing_dir(tmp_path):
    from gauntlet.cli import main
    out = tmp_path / "missing" / "plan.json"
    main(["manifest", "--profile", "ransomware", "--top", "3", "--out", str(out)])
    assert out.exists()


def test_selftest_on_tiny_regression_checkout(tmp_path):
    from gauntlet import cli, selftest

    rule = """title: Defender threat
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags: [attack.t1562.001]
logsource: {product: windows, service: windefend}
detection:
  sel: {EventID: 1116, ThreatName|endswith: 'EICAR_Test_File'}
  condition: sel
"""
    (tmp_path / "rules" / "windows").mkdir(parents=True)
    (tmp_path / "rules" / "windows" / "r.yml").write_text(rule, encoding="utf-8")
    d = tmp_path / "regression_data" / "rules" / "windows" / "builtin" / "r"
    d.mkdir(parents=True)
    (d / "info.yml").write_text(
        "rule_metadata:\n  - id: 11111111-1111-1111-1111-111111111111\n    title: Defender threat\n"
        "regression_tests_info:\n  - name: Positive Detection Test\n    type: evtx\n    match_count: 1\n"
        "    path: regression_data/rules/windows/builtin/r/11111111-1111-1111-1111-111111111111.evtx\n",
        encoding="utf-8")
    ev = {"Event": {"System": {"Channel": "Microsoft-Windows-Windows Defender/Operational",
                               "EventID": {"#attributes": {"Qualifiers": 0}, "#text": 1116},
                               "Provider": {"#attributes": {"Name": "Microsoft-Windows-Windows Defender"}}},
                    "EventData": {"Threat Name": "Virus:DOS/EICAR_Test_File"}}}
    (d / "11111111-1111-1111-1111-111111111111.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
    rep = selftest.run(tmp_path, tmp_path / "out")
    # "Threat Name" in the event matches ThreatName in the rule, as SigmaHQ's own checker does
    assert (rep["tested"], rep["fired"], rep["exact_match_count"]) == (1, 1, 1)
    assert "**1 of 1**" in (tmp_path / "out" / "SELFTEST.md").read_text(encoding="utf-8")
    assert cli.main(["selftest", "--sigma-checkout", str(tmp_path / "nope"), "--out", str(tmp_path)]) == 1


def test_live_replay_completeness_note(tmp_path):
    aud = tmp_path / "splunk" / "attack_techniques" / "T1033" / "a" / "a.log"
    aud.parent.mkdir(parents=True)
    aud.write_text('type=SYSCALL msg=audit(1.0:1): syscall=59 pid=5 exe="/usr/bin/id"\n'
                   'type=PATH msg=audit(1.0:1): name="/usr/bin/id"\n', encoding="utf-8")
    sym = tmp_path / "splunk" / "attack_techniques" / "T1033" / "s" / "s.log"
    sym.parent.mkdir(parents=True)
    sym.write_text("<Event><System><EventID>1</EventID><Channel>Linux-Sysmon/Operational</Channel></System>"
                   "<EventData><Data Name='Image'>/usr/bin/id</Data></EventData></Event>\n", encoding="utf-8")
    st = {"attack_techniques/T1033/a/a.log": "auditd", "attack_techniques/T1033/s/s.log": "sysmon:linux"}
    pa = live.telemetry_profile(mordor.Dataset("A", "", ("T1033",), (aud,), "linux", "splunk"), st)
    ps = live.telemetry_profile(mordor.Dataset("S", "", ("T1033",), (sym,), "linux", "splunk"), st)
    assert (pa["sourcetypes"], pa["execve_records"], pa["syscall_records"]) == (["auditd"], 0, 1)
    assert (ps["sourcetypes"], ps["sysmon_process_creation"]) == (["sysmon:linux"], 1)
    recs = [{"id": "A", "techniques": ["T1033"], **pa, "detected": {"x": False}, "other_rules_fired": {"x": []}},
            {"id": "S", "techniques": ["T1033"], **ps, "detected": {"x": False},
             "other_rules_fired": {"x": ["Local System Accounts Discovery - Linux (T1087.001)"]}}]
    assert live.completeness(recs) == {"T1033": {"recordings": 2, "auditd": 1, "auditd_with_execve": 0,
                                                 "sysmon_linux": 1, "sysmon_with_process_creation": 1}}
    r = {"rules": 1, "audit_records": 2, "labelled_events": 1, "background_events": 1, "techniques": {"T1033": {}},
         "techniques_measured": 0, "techniques_claimed": 1, "technique_coverage": 0.0,
         "technique_coverage_ci95": [0.0, 0.79], "claimed_coverage": 1.0, "background_rules_fired": [],
         "commands": [{"command": "id", "technique": "T1033", "labelled_events": 1, "claimed": True,
                       "measured": False}]}
    md = live.render_md({"run_id": "123", "commit": "abcdef0123", "rulesets": {"x": r}, "replayed_recordings": recs})
    assert "run [123]" in md and "`abcdef0`" in md
    assert "| `id` | T1033 | 1 | yes | no | 0 of 1 | 0 of 1 |" in md
    assert "1 are auditd extracts; 0 of them contain an `EXECVE` record" in md
    assert "(T1087.001)" in md


def test_cli_rejects_unknown_inputs(capsys):
    from gauntlet import cli

    assert cli.main(["sim", "--profile", "ransomware", "--disable-source", "edr"]) == 1
    assert "choose from" in capsys.readouterr().err
    assert cli.main(["predict", "--observed", "T9999"]) == 1
    assert cli.main(["predict", "--observed", "T9999,T1059.001", "-k", "2"]) == 0
    assert "unknown ATT&CK technique id(s) T9999" in capsys.readouterr().err
