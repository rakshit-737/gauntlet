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
    ax.legend(frameon=False, fontsize=9, loc="upper left", bbox_to_anchor=(1.01, 1))
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
        hit = next((k for k, v in enumerate(c, 1) if v >= 0.8), None)
        if hit:
            ax.plot([hit], [80], marker="o", color=SERIES[i], markersize=5)
    ax.axhline(80, color=MUTED, linewidth=1, linestyle="--")
    ax.text(2, 81.5, "80% of the held-out actor's techniques", color=MUTED, fontsize=8)
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


def claimed_vs_measured(ext: dict[str, Any], out: Path, ruleset: str = "sigma-all") -> Path:
    """Dumbbell chart: tag-claimed vs measured technique coverage per data source, with Wilson CIs."""
    rows = [(src, e["rulesets"][ruleset]["claimed_vs_measured"]) for src, e in ext["sources"].items()
            if e.get("rulesets", {}).get(ruleset)]
    fig, ax = plt.subplots(figsize=(7.5, 0.6 * len(rows) + 1.5), dpi=110)
    for i, (_src, cm) in enumerate(rows):
        c, m = 100 * cm["claimed_rate"], 100 * cm["measured_rate"]
        lo, hi = (100 * x for x in cm["measured_ci95"])
        ax.plot([m, c], [i, i], color=GRID, linewidth=6, solid_capstyle="round", zorder=1)
        ax.plot([lo, hi], [i, i], color=SERIES[0], linewidth=1.5, zorder=2)
        ax.scatter([c], [i], color=SERIES[1], s=60, zorder=3, label="claimed by rule tags" if i == 0 else None)
        ax.scatter([m], [i], color=SERIES[0], s=60, zorder=3, label="measured (95% CI)" if i == 0 else None)
        ax.text(c + 1.5, i, f"+{c - m:.0f} pts", va="center", fontsize=8, color=MUTED)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{s} (n={cm['techniques']})" for s, cm in rows], color=INK)
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("recorded techniques covered (%)", color=MUTED, fontsize=9)
    ax.set_title(f"Claimed vs measured ATT&CK coverage, SigmaHQ {ruleset}", color=INK, fontsize=11, loc="left")
    _style(ax)
    ax.legend(frameon=False, fontsize=9, loc="upper left", bbox_to_anchor=(1.01, 1))
    fig.tight_layout()
    p = out / "claimed_vs_measured.png"
    fig.savefig(p)
    plt.close(fig)
    return p
