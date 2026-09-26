import pytest

from gauntlet import predict, stats


def test_wilson_bounds():
    lo, hi = stats.wilson(36, 54)
    assert 0.5 < lo < 36 / 54 < hi < 0.8
    assert stats.wilson(0, 0) == (0.0, 0.0)
    assert stats.wilson(0, 10)[0] == 0.0
    assert stats.wilson(10, 10)[1] == 1.0


def test_bootstrap_ci_contains_mean_and_is_deterministic():
    vals = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    lo, hi = stats.bootstrap_ci(vals)
    assert lo <= 0.35 <= hi
    assert stats.bootstrap_ci(vals) == (lo, hi)
    assert stats.bootstrap_ci([0.7]) == (0.7, 0.7)
    assert stats.bootstrap_ci([]) == (0.0, 0.0)


def test_paired_bootstrap():
    r = stats.paired_bootstrap_ci([3, 4, 5], [1, 2, 3])
    assert r["mean_diff"] == 2 and r["ci95"] == [2.0, 2.0] and r["n"] == 3
    with pytest.raises(ValueError):
        stats.paired_bootstrap_ci([1], [1, 2])


def test_predict_evaluate_seeds_reports_spread_and_ci():
    sets = [{f"t{i}" for i in range(j, j + 12)} for j in range(6)]
    res = predict.evaluate_seeds(sets, seeds=range(3), min_size=10)
    assert res["across_seeds"]["seeds"] == [0, 1, 2]
    assert "recall@10_sd" in res["across_seeds"]["cooccurrence"]
    assert "paired_recall@10" in res and "ci95" in res
