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
    res = [ReplayResult("d1", ("T1033",), 5, {"auditd-exec": 5}, {"a": {"auditd-exec": 1}}),
           ReplayResult("d2", ("T1082",), 5, {"auditd-exec": 5}, {}),
           ReplayResult("d3", ("T1082.001",), 5, {"auditd": 5}, {})]
    out = extended.claimed_vs_measured(res, rules)
    assert out["claimed"] == 3 and out["measured"] == 1
    gaps = {r["technique"]: r["gap"] for r in out["rows"]}
    assert gaps == {"T1033": None, "T1082": "rule_logic_gap", "T1082.001": "telemetry_gap"}


def test_exact_tests():
    assert stats.mcnemar_exact(10, 0) == pytest.approx(2 * 0.5 ** 10)
    assert stats.binom_two_sided(0, 4) == 0.125
    assert stats.mcnemar_exact(0, 0) == 1.0


def test_splunk_and_compound_loaders(tmp_path):
    man = {"recordings": [{"id": "SPLK-1", "title": "t", "techniques": ["T1033"],
                           "files": [{"path": "datasets/attack_techniques/T1033/x/a.log", "sourcetype": "auditd"}]},
                          {"id": "SPLK-2", "title": "w", "techniques": ["T1003.001"],
                           "files": [{"path": "datasets/attack_techniques/T1003.001/y/b.log",
                                      "sourcetype": "XmlWinEventLog"}]}]}
    mp = tmp_path / "m.json"
    mp.write_text(json.dumps(man))
    ds = mordor.load_splunk(tmp_path, mp)
    assert [(d.id, d.tactic_dir, d.source) for d in ds] == [("SPLK-1", "linux", "splunk"),
                                                           ("SPLK-2", "windows", "splunk")]
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
    assert "RedGap publishes 1/2" in published.render_md({"ctid": c, "redgap": r})


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
