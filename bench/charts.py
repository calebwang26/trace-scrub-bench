"""The two plots that go with the leaderboard."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, GRAY = "#2a78d6", "#8a8984"
# One hue, light to dark: a darker cell means more was removed.
BLUES = LinearSegmentedColormap.from_list("blues", ["#eef4fd", "#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"])

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "text.color": INK, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2, "axes.edgecolor": GRID, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE})

VARIANT_LABELS = {"plain": "plain", "split": "split over\n2 lines", "base64": "base64", "json_escaped": "escaped\nJSON", "adversarial": "hand-written\nadversarial"}


def _grid(ax, results: list[dict], key: str, columns: list[str], labels: list[str], title: str, show_names: bool) -> None:
    values = [[r[key].get(c, 0.0) for c in columns] for r in results]
    ax.imshow(values, cmap=BLUES, vmin=0, vmax=1, aspect="auto")
    for y, row in enumerate(values):
        for x, v in enumerate(row):
            ax.text(x, y, f"{100 * v:.0f}", ha="center", va="center", fontsize=8.5, color="#ffffff" if v > 0.55 else INK)
    ax.set_xticks(range(len(columns)), labels, rotation=40 if "\n" not in "".join(labels) else 0, ha="right" if "\n" not in "".join(labels) else "center")
    ax.set_yticks(range(len(results)), [r["name"] for r in results] if show_names else [])
    ax.set_xticks([x - 0.5 for x in range(1, len(columns))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(results))], minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="both", length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_title(title, loc="left", fontsize=10, color=INK, pad=8)


def recall_heatmap(results: list[dict], path: str | Path) -> None:
    """Recall (% of planted items removed) per scrubber, by type & by hard-case variant."""
    types = sorted({t for r in results for t in r["recall_by_type"]}, key=lambda t: -sum(r["recall_by_type"].get(t, 0) for r in results))
    variants = [v for v in VARIANT_LABELS if any(v in r["recall_by_variant"] for r in results)]
    fig, (left, right) = plt.subplots(1, 2, figsize=(11.5, 1.3 + 0.42 * len(results)), gridspec_kw={"width_ratios": [len(types), len(variants) * 1.25]}, constrained_layout=True)
    _grid(left, results, "recall_by_type", types, [t.replace("_", " ") for t in types], "Recall by type of sensitive item (% removed)", True)
    _grid(right, results, "recall_by_variant", variants, [VARIANT_LABELS[v] for v in variants], "Recall by how the item was hidden (% removed)", False)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def _scatter(ax, results: list[dict], xlim: tuple[float, float], title: str) -> None:
    placed: list[tuple[float, float]] = []
    for r in results:
        x, y = 100 * r["utility_kept"], 100 * r["severity_score"]
        if not xlim[0] <= x <= xlim[1]:
            continue
        baseline = r["name"] in ("do-nothing", "redact-everything")
        ax.scatter([x], [y], s=70, color=GRAY if baseline else BLUE, edgecolor=SURFACE, linewidth=2, zorder=3, clip_on=False)
        right_side = x - xlim[0] < 0.25 * (xlim[1] - xlim[0])
        # if another point sits close by, put this label below its dot instead of above
        crowded = any(abs(x - px) < 0.2 * (xlim[1] - xlim[0]) and abs(y - py) < 6 for px, py in placed)
        placed.append((x, y))
        ax.annotate(r["name"], (x, y), xytext=(8 if right_side else -8, -9 if crowded else 7), textcoords="offset points",
                    ha="left" if right_side else "right", va="top" if crowded else "bottom", fontsize=8.5, color=INK)
    ax.set_xlim(*xlim)
    ax.set_ylim(-4, 104)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)
    ax.set_xlabel("Utility kept (% of non-sensitive characters that survive)")
    ax.set_title(title, loc="left", fontsize=10, color=INK, pad=8)


def recall_vs_utility(results: list[dict], path: str | Path) -> None:
    """Risk removed against utility kept. The best place to be is the top right corner."""
    real = [100 * r["utility_kept"] for r in results if r["name"] != "redact-everything"]
    low = min(real) if real else 99.0
    zoom_from = min(99.0, max(0.0, low - 0.15 * (100 - low) - 0.05))
    fig, (full, zoom) = plt.subplots(1, 2, figsize=(11.5, 4.3), constrained_layout=True)
    _scatter(full, results, (-3, 103), "Risk removed vs utility kept: the full range")
    full.set_ylabel("Severity-weighted share of risk removed (%)")
    _scatter(zoom, results, (zoom_from, 100 + 0.04 * (100 - zoom_from)), "Zoom on the right edge, where the real scrubbers sit")
    fig.savefig(path, dpi=150)
    plt.close(fig)
