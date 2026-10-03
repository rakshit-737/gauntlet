"""Small, dependency-free uncertainty helpers used by the benchmark.

* :func:`wilson` -- 95% Wilson score interval for a proportion (coverage, recall).
* :func:`pct` / :func:`fmt_ci` -- the single place results are rounded for display.
* :func:`bootstrap_ci` -- percentile bootstrap CI of the mean of per-unit values
  (e.g. one value per held-out ATT&CK group).
* :func:`paired_bootstrap_ci` -- CI of the mean *difference* between two strategies
  measured on the same units (like-for-like comparison).
* :func:`weighted_bootstrap_ci` -- CI of a weighted proportion (threat-weighted coverage),
  resampling techniques.

All resampling uses a fixed seed so results are reproducible. Nothing here rounds: the
generators store full-precision values and the renderers round exactly once (rounding a
bound to 4 decimals first and to 1 decimal of a percent later moved some bounds by 0.1).
"""
from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """95% Wilson score interval for ``successes`` out of ``n``, unrounded.

    The bounds are exactly 0.0 when ``successes == 0`` and exactly 1.0 when ``successes == n``.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    lo = 0.0 if successes <= 0 else max(0.0, centre - half)
    hi = 1.0 if successes >= n else min(1.0, centre + half)
    return (lo, hi)


def pct(x: float, digits: int = 1) -> str:
    """A proportion as a percentage string, rounded once (``0.80 -> '80.0'``)."""
    return f"{100 * x:.{digits}f}"


def fmt_ci(ci: Sequence[float] | None, digits: int = 1, unit: str = "") -> str:
    """``' [lo, hi]'`` in percent from an unrounded proportion interval, rounded once."""
    if not ci:
        return ""
    return f" [{pct(ci[0], digits)}{unit}, {pct(ci[1], digits)}{unit}]"


def bootstrap_ci(values: Sequence[float], n_boot: int = 2000, alpha: float = 0.05,
                 seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean of ``values`` (fixed ``seed``, ``n_boot`` resamples), unrounded."""
    vals = list(values)
    if not vals:
        return (0.0, 0.0)
    if len(vals) == 1:
        return (vals[0], vals[0])
    rnd = random.Random(seed)
    n = len(vals)
    means = sorted(statistics.fmean(vals[rnd.randrange(n)] for _ in range(n)) for _ in range(n_boot))
    lo = means[int(alpha / 2 * n_boot)]
    hi = means[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (lo, hi)


def weighted_bootstrap_ci(hits: Sequence[float], weights: Sequence[float], n_boot: int = 2000,
                          alpha: float = 0.05, seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap CI of a weighted proportion sum(w*hit)/sum(w), resampling units (techniques)."""
    pairs = [(h, w) for h, w in zip(hits, weights, strict=True)]
    if not pairs or not sum(w for _, w in pairs):
        return (0.0, 0.0)
    rnd = random.Random(seed)
    n = len(pairs)
    est = []
    for _ in range(n_boot):
        num = den = 0.0
        for _ in range(n):
            h, w = pairs[rnd.randrange(n)]
            num += w * h
            den += w
        est.append(num / den if den else 0.0)
    est.sort()
    return (est[int(alpha / 2 * n_boot)], est[min(n_boot - 1, int((1 - alpha / 2) * n_boot))])


def paired_bootstrap_ci(a: Sequence[float], b: Sequence[float], n_boot: int = 2000, alpha: float = 0.05,
                        seed: int = 0) -> dict[str, float]:
    """Mean of ``a - b`` with a bootstrap CI; ``a`` and ``b`` are aligned per unit."""
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    diff = [x - y for x, y in zip(a, b, strict=True)]
    lo, hi = bootstrap_ci(diff, n_boot, alpha, seed)
    return {"mean_diff": statistics.fmean(diff) if diff else 0.0, "ci95": [lo, hi], "n": len(diff)}


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
