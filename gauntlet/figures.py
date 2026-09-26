"""Static PNG figures for the README (matplotlib, optional dependency)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# validated default categorical order (blue, orange, aqua, yellow, magenta)
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
INK, MUTED, GRID = "#1f1f1e", "#6b6a66", "#e4e3df"


def _style(ax) -> None:
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def tactic_coverage(summaries: dict[str, Any], out: Path) -> Path:
    names = list(summaries)
    tactics = sorted({k for s in summaries.values() for k in s.by_tactic()},
                     key=lambda k: -summaries[names[-1]].by_tactic().get(k, (0, 1))[1])
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(tactics) + 1.4), dpi=110)
    h = 0.8 / len(names)
    for i, n in enumerate(names):
        bt = summaries[n].by_tactic()
        vals = [100 * bt.get(t, (0, 1))[0] / max(bt.get(t, (0, 1))[1], 1) for t in tactics]
        ys = [j + (i - (len(names) - 1) / 2) * h for j in range(len(tactics))]
        ax.barh(ys, vals, height=h * 0.9, color=SERIES[i], label=n, edgecolor="white", linewidth=1)
    ax.set_yticks(range(len(tactics)))
    ax.set_yticklabels([f"{t} (n={summaries[names[-1]].by_tactic()[t][1]})" for t in tactics], color=INK)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("techniques with an on-target detection (%)", color=MUTED, fontsize=9)
    ax.set_title("Detection coverage per ATT&CK tactic on OTRF recordings", color=INK, fontsize=11, loc="left")
    _style(ax)
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    fig.tight_layout()
    p = out / "tactic_coverage.png"
    fig.savefig(p)
    plt.close(fig)
    return p


def prioritization_curves(report: dict[str, Any], out: Path, profile: str = "ransomware") -> Path:
    d = report["prioritization"][profile]
    fig, ax = plt.subplots(figsize=(7.5, 4.2), dpi=110)
    order = ["cti", "relevance", "prevalence", "breadth", "random"]
    for i, s in enumerate(order):
        c = d["mean_curves"].get(s)
        if not c:
            continue
        xs = range(1, len(c) + 1)
        ax.plot(xs, [100 * v for v in c], color=SERIES[i], linewidth=2, label=s)
        ax.annotate(s, (len(c), 100 * c[-1]), xytext=(4, 0), textcoords="offset points",
                    color=INK, fontsize=8, va="center")
    ax.set_xlabel("techniques emulated (in priority order)", color=MUTED, fontsize=9)
    ax.set_ylabel("held-out actor's techniques covered (%)", color=MUTED, fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title(f"CTI-prioritized vs breadth-first emulation - {profile} profile "
                 f"(leave-one-group-out, n={d['groups_evaluated']})", color=INK, fontsize=10, loc="left")
    _style(ax)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    fig.tight_layout()
    p = out / f"prioritization_{profile}.png"
    fig.savefig(p)
    plt.close(fig)
    return p


def make_all(report: dict[str, Any], summaries: dict[str, Any], out: Path) -> list[Path]:
    return [tactic_coverage(summaries, out), prioritization_curves(report, out)]
