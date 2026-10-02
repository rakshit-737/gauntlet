"""Small, dependency-free uncertainty helpers used by the benchmark.

* :func:`wilson` -- 95% Wilson score interval for a proportion (coverage, recall).
* :func:`bootstrap_ci` -- percentile bootstrap CI of the mean of per-unit values
  (e.g. one value per held-out ATT&CK group).
* :func:`paired_bootstrap_ci` -- CI of the mean *difference* between two strategies
  measured on the same units (like-for-like comparison).

All resampling uses a fixed seed so results are reproducible.
"""
from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def bootstrap_ci(values: Sequence[float], n_boot: int = 2000, alpha: float = 0.05,
                 seed: int = 0) -> tuple[float, float]:
    vals = list(values)
    if not vals:
        return (0.0, 0.0)
    if len(vals) == 1:
        return (round(vals[0], 4), round(vals[0], 4))
    rnd = random.Random(seed)
    n = len(vals)
    means = sorted(statistics.fmean(vals[rnd.randrange(n)] for _ in range(n)) for _ in range(n_boot))
    lo = means[int(alpha / 2 * n_boot)]
    hi = means[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (round(lo, 4), round(hi, 4))


def paired_bootstrap_ci(a: Sequence[float], b: Sequence[float], n_boot: int = 2000, alpha: float = 0.05,
                        seed: int = 0) -> dict[str, float]:
    """Mean of ``a - b`` with a bootstrap CI; ``a`` and ``b`` are aligned per unit."""
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    diff = [x - y for x, y in zip(a, b, strict=True)]
    lo, hi = bootstrap_ci(diff, n_boot, alpha, seed)
    return {"mean_diff": round(statistics.fmean(diff), 4) if diff else 0.0, "ci95": [lo, hi], "n": len(diff)}


def binom_two_sided(k: int, n: int) -> float:
    """Exact two-sided binomial (p=0.5) test p-value: sign test / exact McNemar on ``n`` discordant pairs."""
    if n <= 0:
        return 1.0
    k = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def mcnemar_exact(b: int, c: int) -> float:
    """Exact McNemar p-value for paired binary outcomes with ``b`` and ``c`` discordant pairs."""
    return binom_two_sided(min(b, c), b + c)
