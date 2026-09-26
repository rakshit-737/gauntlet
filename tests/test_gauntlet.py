import json
import re
from pathlib import Path

import pytest

from gauntlet import cli, cti, detect, plans, range_sim, score
from gauntlet.models import Event, Outcome

RULES = Path(__file__).resolve().parent.parent / "rules"


def test_prioritize_orders_by_relevance_times_prevalence():
    ranked = cti.prioritize(cti.PROFILES["ransomware"])
    scores = [r.score for r in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0].technique.id == "T1059.001"
    assert len(cti.prioritize(cti.PROFILES["ransomware"], top_n=3)) == 3


def test_every_catalog_technique_has_simulated_step():
    assert set(cti.CATALOG) == set(plans.STEPS)


def test_plans_are_inert_no_real_payloads():
    """Safety guard: simulated steps must not carry real URLs/IPs outside lab ranges."""
    blob = json.dumps([s.events for s in plans.STEPS.values()])
    for host in re.findall(r"https?://([^/\s\"]+)", blob):
        assert host.endswith(".invalid")
    for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", blob):
        assert ip.startswith("10.66.")


def test_generator_deterministic_and_labelled():
    plan = plans.build_plan(cti.prioritize(cti.PROFILES["ransomware"]))
    a = range_sim.generate(plan, seed=1)
    b = range_sim.generate(plan, seed=1)
    assert [(e.host, e.fields) for e in a] == [(e.host, e.fields) for e in b]
    assert {e.technique_id for e in a if e.technique_id} == {s.technique_id for s in plan}
    assert any(e.technique_id is None for e in a)


def test_telemetry_gap_suppresses_events():
    plan = [plans.STEPS["T1566.001"]]
    rng = range_sim.without_sources(range_sim.DEFAULT_RANGE, {"mail"})
    assert not [e for e in range_sim.generate(plan, rng, noise=0)]


@pytest.mark.parametrize("mod,actual,expected,ok", [
    ("contains", "vssadmin delete SHADOWS", "delete shadows", True),
    ("startswith", "C:\\Windows\\x", "c:\\windows", True),
    ("endswith", "a.locked", ".LOCKED", True),
    ("re", "powershell -enc abc", r"\s-enc\s", True),
    ("gte", 7, 5, True),
    ("gte", "x", 5, False),
    (None, "abc", "abd", False),
])
def test_modifiers(mod, actual, expected, ok):
    assert detect._match_value(actual, mod, expected) is ok


def test_filter_condition_excludes_system32_lsass_access():
    rule = next(r for r in detect.load_rules(RULES) if r.id == "lsass_access")
    bad = Event("WS01", "sysmon", {"EventID": 10, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                                   "SourceImage": "C:\\Users\\Public\\tool.exe", "GrantedAccess": "0x1010"})
    good = Event("WS01", "sysmon", dict(bad.fields, SourceImage="C:\\Windows\\System32\\svchost.exe"))
    assert detect.matches(rule, bad) and not detect.matches(rule, good)


def test_threshold_distinct_users():
    rule = next(r for r in detect.load_rules(RULES) if r.id == "password_spray")
    one_user = [Event("DC01", "auth", {"result": "failure", "user": "bob", "src_ip": "1"}) for _ in range(9)]
    spray = [Event("DC01", "auth", {"result": "failure", "user": f"u{i}", "src_ip": "2"}) for i in range(5)]
    alerts = detect.run([rule], one_user + spray)
    assert len(alerts) == 5 and all(a.event.fields["src_ip"] == "2" for a in alerts)


def test_unsupported_condition_rejected():
    with pytest.raises(ValueError):
        detect.load_rule({"id": "x", "title": "x", "techniques": [], "logsource": "sysmon",
                          "detection": {"selection": {}, "condition": "1 of them"}})


def test_all_shipped_rules_load():
    rules = detect.load_rules(RULES)
    assert len(rules) >= 7
    assert all(set(r.techniques) <= set(cti.CATALOG) for r in rules)


def test_coverage_gap_then_fix(tmp_path):
    """Demo scenario 2: credential dumping missed -> add rule -> detected."""
    for p in RULES.glob("*.json"):
        if p.stem != "lsass_access":
            (tmp_path / p.name).write_text(p.read_text())
    _, before = cli.run_pipeline("ransomware", tmp_path)
    res = {r.technique_id: r for r in before.results}
    assert res["T1003.001"].outcome == Outcome.MISSED
    (tmp_path / "lsass_access.json").write_text((RULES / "lsass_access.json").read_text())
    _, after = cli.run_pipeline("ransomware", tmp_path)
    assert {r.technique_id: r for r in after.results}["T1003.001"].outcome == Outcome.DETECTED
    assert after.coverage > before.coverage


def test_partial_outcome():
    ranked = cti.prioritize(cti.PROFILES["ransomware"])
    plan = plans.build_plan(ranked)
    events = range_sim.generate(plan, noise=0)
    rule = next(r for r in detect.load_rules(RULES) if r.id == "ransom_ext")
    alerts = detect.run([rule], events)[:1]  # only one of three events caught
    rep = score.score("x", ranked, plan, events, alerts, range_sim.DEFAULT_RANGE)
    assert {r.technique_id: r for r in rep.results}["T1486"].outcome == Outcome.PARTIAL


def test_gap_recommendations_group_telemetry():
    rng = range_sim.without_sources(range_sim.DEFAULT_RANGE, {"sysmon"})
    ranked, rep = cli.run_pipeline("ransomware", RULES, rng=rng)
    recs = score.gap_recommendations(rep, ranked)
    assert recs[0]["kind"] == "telemetry" and "sysmon" in recs[0]["action"]
    assert len(recs[0]["techniques"]) >= 5


def test_regression_diff_and_cli_exit_code(tmp_path, capsys):
    base = tmp_path / "base.json"
    assert cli.main(["run", "--json", str(base)]) == 0
    assert cli.main(["run", "--baseline", str(base)]) == 0
    broken = tmp_path / "rules"
    broken.mkdir()
    for p in RULES.glob("*.json"):
        if p.stem != "vss_delete":
            (broken / p.name).write_text(p.read_text())
    assert cli.main(["run", "--rules", str(broken), "--baseline", str(base)]) == 2
    assert "T1490: detected -> missed" in capsys.readouterr().err


def test_false_positive_counting():
    ranked, rep = cli.run_pipeline("ransomware", RULES)
    assert rep.false_positives == 0
    assert 0 < rep.coverage < 1
    assert set(rep.by_tactic()) == {r.tactic for r in rep.results}


def test_cli_plan_and_profiles(capsys):
    assert cli.main(["profiles"]) == 0
    assert cli.main(["plan", "--profile", "espionage", "--top", "3"]) == 0
    assert cli.main(["plan", "--profile", "nope"]) == 1
