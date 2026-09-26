"""Tests for the real-data pipeline using tiny committed-in-code fixtures."""
import json

import pytest
from conftest import mini_bundle

from gauntlet import atomics, cli, coverage, mordor, paths, predict, prioritize, replay
from gauntlet.attack import KnowledgeBase, load_kb, parse_stix
from gauntlet.sigma import load_rules


# ------------------------------------------------------------------ ATT&CK
def test_parse_stix_filters_revoked_and_rolls_up_software(mini_kb):
    assert "T9999" not in mini_kb.techniques
    assert mini_kb.tactic_order == ("initial-access", "execution")
    # G0002 uses S0001 which uses T1486 -> group inherits it
    assert "T1486" in mini_kb.groups["G0002"].techniques
    assert mini_kb.name_of("T1059.001") == "Command and Scripting Interpreter: PowerShell"
    assert mini_kb.find_group("ransomax").id == "G0001"
    assert mini_kb.tactic_of("T1059.001") == "execution"


def test_revoked_ids_map_to_replacement(mini_kb):
    assert mini_kb.revoked == {"T9999": "T1490"}
    assert mini_kb.canonical("T9999") == "T1490"
    assert mini_kb.canonical("T9999.001") == "T1490"      # sub of a revoked parent
    assert mini_kb.canonical("T1059.001") == "T1059.001"
    assert load_kb().canonical("T1086") == "T1059.001"      # real ATT&CK: PowerShell re-id


def test_prevalence_counts_parent_rollup(mini_kb):
    prev = mini_kb.prevalence()
    assert prev["T1059.001"] == pytest.approx(1.0)
    assert prev["T1059"] == pytest.approx(1.0)
    assert prev["T1566.001"] == pytest.approx(1 / 3)


def test_kb_json_roundtrip(mini_kb, tmp_path):
    from gauntlet.attack import write_kb
    p = write_kb(mini_kb, tmp_path / "kb.json")
    kb2 = KnowledgeBase.from_json(json.loads(p.read_text()))
    assert kb2.groups["G0002"].techniques == mini_kb.groups["G0002"].techniques
    assert kb2.techniques == mini_kb.techniques


def test_shipped_kb_is_real_attack():
    kb = load_kb()
    assert kb.version.startswith("19")
    assert len(kb.techniques) > 600 and len(kb.groups) > 100
    assert kb.find_group("APT29") is not None
    assert "T1059.001" in kb.find_group("APT29").techniques


# ------------------------------------------------------------------ prioritization
def test_profile_from_descriptions_and_explicit(mini_kb):
    assert [g.id for g in prioritize.profile_groups(mini_kb, "ransomware")] == ["G0001", "G0002"]
    assert [g.id for g in prioritize.profile_groups(mini_kb, "SpyC,G0001")] == ["G0003", "G0001"]
    with pytest.raises(KeyError):
        prioritize.profile_groups(mini_kb, "nobody")


def test_rank_strategies(mini_kb):
    groups = prioritize.profile_groups(mini_kb, "ransomware")
    rel, prev = prioritize.relevance(groups), mini_kb.prevalence()
    cands = ["T1059.001", "T1003.001", "T1486", "T1566.001", "T1082"]
    cti = [r.technique for r in prioritize.rank(cands, rel, prev, "cti")]
    assert cti[0] == "T1059.001"                       # used by both ransomware groups and everyone
    assert cti.index("T1486") < cti.index("T1566.001")  # profile-relevant beats irrelevant
    assert [r.technique for r in prioritize.rank(cands, rel, prev, "breadth")] == sorted(cands)
    r1 = [r.technique for r in prioritize.rank(cands, rel, prev, "random", seed=1)]
    assert sorted(r1) == sorted(cands)


def test_recall_curve_and_steps():
    c = prioritize.recall_curve(["a", "x", "b", "y"], {"a", "b"})
    assert c == [0.5, 0.5, 1.0, 1.0]
    assert prioritize.steps_to(c, 0.8) == 3
    assert prioritize.steps_to([0.1], 0.5) == 2


def test_evaluate_logo_on_shipped_kb():
    kb = load_kb()
    universe = {t for t in atomics.load_index() if t in kb.techniques}
    res = prioritize.evaluate_logo(kb, "ransomware", universe, random_seeds=3)
    assert res["groups_evaluated"] >= 5
    s = res["strategies"]
    assert set(s) == set(prioritize.STRATEGIES)
    # CTI-driven orderings must beat breadth-first on held-out actors
    assert s["cti"]["auc"] > s["breadth"]["auc"]
    assert len(res["mean_curves"]["cti"]) == 100


# ------------------------------------------------------------------ prediction
def test_cooccurrence_beats_nothing_and_is_consistent():
    sets = [{"a", "b", "c"}, {"a", "b", "d"}, {"a", "b", "c"}, {"x", "y"}]
    m = predict.CooccurrenceModel(sets)
    assert m.predict({"a"}, k=1)[0][0] == "b"
    m.add({"a", "b", "c"}, -1)
    assert m.n["c"] == 1 and m.n_sets == 3
    res = predict.evaluate([{f"t{i}" for i in range(12)} for _ in range(5)], min_size=10)
    assert res["groups_evaluated"] == 5
    assert set(res["models"]) == {"cooccurrence", "popularity"}


# ------------------------------------------------------------------ mordor + replay + coverage
def test_mordor_catalog(mini_data):
    cat = mordor.load_catalog(mini_data)
    assert [d.techniques for d in cat] == [("T1003.001",), ("T1490",), ("T1082",)]
    assert all(d.available for d in cat) and len(cat[0].files) == 1   # network file ignored
    evs = list(mordor.iter_events(cat[0].files[0]))
    assert len(evs) == 3 and mordor.normalize(evs[0])[:2] == ("microsoft-windows-sysmon/operational", 10)


def test_replay_and_coverage(mini_data, mini_kb):
    cat = mordor.load_catalog(mini_data)
    rules = load_rules(mini_data / "sigma_rules").rules
    idx = replay.RuleIndex(rules)
    res = [replay.replay_dataset(idx, d) for d in cat]
    assert res[0].fired() == {"r-lsass", "r-whoami"}
    assert res[1].fired() == {"r-vss", "r-whoami"}          # Security 4688 field mapping works
    assert res[1].fired(drop_channels=["security"]) == {"r-whoami"}
    rmap = {r.id: r for r in rules}
    s = coverage.score("mini", res, rmap, mini_kb)
    out = {t.technique: t.outcome for t in s.techniques}
    assert out == {"T1003.001": "detected", "T1490": "detected", "T1082": "missed"}
    assert s.technique_coverage == pytest.approx(2 / 3)
    assert s.off_target_rules_per_dataset == pytest.approx(1.0)   # whoami fires everywhere, off-target
    assert s.weighted({"T1003.001": 1, "T1490": 1, "T1082": 2}) == pytest.approx(0.5)
    greedy = coverage.greedy_rule_selection(res, rmap, top=5)
    assert [g["id"] for g in greedy] == ["r-vss", "r-lsass"] or [g["id"] for g in greedy] == ["r-lsass", "r-vss"]
    abl = {a["channel"]: a["techniques_lost"] for a in coverage.channel_ablation(res, rmap, ["security"])}
    assert abl == {"security": 1}
    layer = coverage.navigator_layer(s, "19.2")
    assert layer["versions"]["attack"] == "19" and len(layer["techniques"]) == 3
    exact = coverage.score("x", res, rmap, mini_kb, exact=True)
    assert exact.technique_coverage == pytest.approx(2 / 3)


def test_on_target_family_vs_exact():
    assert coverage.on_target(["T1059"], ["T1059.001"])
    assert not coverage.on_target(["T1059"], ["T1059.001"], exact=True)
    assert not coverage.on_target([], ["T1059.001"])


def test_replay_many_parallel_and_cache(mini_data):
    cat = mordor.load_catalog(mini_data)
    cache = mini_data / "cache.json"
    spec = f"sigma-all:{mini_data / 'sigma_rules'}"
    a = replay.replay_many(spec, cat, workers=2, cache=cache, progress=False)
    assert cache.exists()
    b = replay.replay_many(spec, cat, workers=2, cache=cache, progress=False)
    assert [x.hits for x in a] == [x.hits for x in b]
    core = replay.load_ruleset(f"sigma-core:{mini_data / 'sigma_rules'}")
    assert {r.id for r in core} == {"r-lsass", "r-vss"}


def test_legacy_rules_run_on_real_style_events(mini_data):
    rules = replay.load_ruleset(f"legacy:{paths.REPO / 'rules'}")
    ids = {r.id for r in rules}
    assert "lsass_access" in ids and "password_spray" not in ids   # threshold/auth rules not adaptable
    idx = replay.RuleIndex(rules)
    res = replay.replay_dataset(idx, mordor.load_catalog(mini_data)[0])
    assert "lsass_access" in res.fired()


# ------------------------------------------------------------------ ART + CLI
def test_art_index_and_manifest():
    csv = ("Tactic,Technique #,Technique Name,Test #,Test Name,Test GUID,Executor Name\n"
           "impact,T1490,Inhibit,1,Delete shadows,g-1,command_prompt\n"
           "impact,T1490,Inhibit,2,Wbadmin,g-2,command_prompt\n"
           "stealth,T1490,Inhibit,1,Delete shadows,g-1,command_prompt\n")
    idx = atomics.parse_index_csv(csv)
    assert [t["guid"] for t in idx["T1490"]] == ["g-1", "g-2"]
    m = atomics.manifest(["T1490", "T0000"], idx, per_technique=1)
    assert m[0]["invoke"] == ["Invoke-AtomicTest T1490 -TestGuids g-1"] and m[1]["atomic_tests"] == []
    shipped = atomics.load_index()
    assert len(shipped) > 200 and "T1003.001" in shipped


def test_cli_real_commands(capsys, tmp_path):
    assert cli.main(["profiles"]) == 0
    assert "ransomware" in capsys.readouterr().out
    assert cli.main(["plan", "--profile", "APT29", "--top", "5"]) == 0
    assert cli.main(["plan", "--profile", "ransomware", "--strategy", "breadth", "--top", "3"]) == 0
    assert cli.main(["predict", "--observed", "T1566.001,T1059.001", "-k", "3"]) == 0
    out = tmp_path / "m.json"
    assert cli.main(["manifest", "--profile", "ransomware", "--top", "4", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert len(doc["steps"]) == 4 and "DRY RUN" in doc["safety"]
    assert cli.main(["--data-dir", str(tmp_path), "replay"]) == 1   # no data -> clean error


def test_cli_replay_and_regression(mini_data, tmp_path, capsys, monkeypatch):
    # custom KB via STIX file in the data dir
    (mini_data / "attack").mkdir()
    (paths.attack_bundle(mini_data)).write_text(json.dumps(mini_bundle()))
    (mini_data / "sigma").mkdir()
    paths.sigma_zip(mini_data).write_bytes(b"")  # presence marker only
    base = tmp_path / "base.json"
    rules = mini_data / "sigma_rules"
    args = ["--data-dir", str(mini_data), "replay", "--profile", "RansomA,RansomB,SpyC", "--workers", "1"]
    assert cli.main([*args, "--ruleset", f"sigma-all:{rules}", "--json", str(base),
                     "--navigator", str(tmp_path / "layer.json")]) == 0
    assert json.loads((tmp_path / "layer.json").read_text())["domain"] == "enterprise-attack"
    (rules / "vss.yml").unlink()
    assert cli.main([*args, "--ruleset", f"sigma-all:{rules}", "--baseline", str(base)]) == 2
    assert "T1490: detected -> missed" in capsys.readouterr().err


# ------------------------------------------------------------------ real data (skipped in CI)
realdata = pytest.mark.skipif(not paths.have_real_data(), reason="datasets not downloaded")


@pytest.mark.realdata
@realdata
def test_real_sigma_rules_mostly_supported():
    rs = load_rules(paths.sigma_zip(), subdir_prefix=("rules/windows/",))
    assert len(rs.rules) > 2000
    assert len(rs.unsupported) / (len(rs.rules) + len(rs.unsupported)) < 0.05


@pytest.mark.realdata
@realdata
def test_real_mordor_lsass_recording_detected():
    cat = [d for d in mordor.load_catalog(paths.data_dir()) if d.available
           and any(t.startswith("T1003") for t in d.techniques)]
    assert cat
    rules = replay.load_ruleset(f"sigma-all:{paths.sigma_zip()}")
    idx = replay.RuleIndex(rules)
    rmap = {r.id: r for r in rules}
    hit = sum(bool({r for r in replay.replay_dataset(idx, d).fired()
                    if coverage.on_target(rmap[r].techniques, d.techniques)}) for d in cat[:5])
    assert hit >= 1


def test_parse_stix_version_from_collection():
    b = mini_bundle()
    b["objects"].append({"type": "x-mitre-collection", "id": "c", "x_mitre_version": "19.2"})
    assert parse_stix(b).version == "19.2"


def test_iter_events_tar_gz(tmp_path):
    import io
    import tarfile
    data = b'{"Channel": "Security", "EventID": 4624}\n{"Channel": "System", "EventID": 7045}\n'
    p = tmp_path / "rec.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        info = tarfile.TarInfo("rec.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    assert [e["EventID"] for e in mordor.iter_events(p)] == [4624, 7045]
