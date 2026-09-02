#!/usr/bin/env python3
"""Regenerate the milestone-distribution figures used in the revision paper.

The script reads the adjudicated annotations, counts milestone headers of the
form ``M<N>.``, assigns each benchmark instance to one primary vulnerability
category, validates the published aggregate counts, and writes the XBOW and
Vulhub PNG figures directly to the paper's Image directory.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


MILESTONE_PATTERN = re.compile(r"(?m)^M\d+\.")

XBOW_ORDER = [
    "SQLi",
    "XSS",
    "Command Injection",
    "SSTI",
    "Auth Failures",
    "IDOR",
    "SSRF",
    "Path/LFI",
    "XXE",
    "Crypto",
]

VULHUB_ORDER = ["Auth Failures", "Path/LFI", "RCE"]


def primary_category(machine_id: str, tag_text: str) -> str:
    """Map multi-label CSV tags to the primary categories used in the figures."""
    tags = {tag.strip().lower() for tag in tag_text.split(",")}

    if machine_id.startswith("CVE-"):
        if "privilege escalation" in tags or "default credentials" in tags:
            return "Auth Failures"
        if "path traversal" in tags or "lfi" in tags:
            return "Path/LFI"
        return "RCE"

    if "xss" in tags:
        return "XSS"
    if "sqli" in tags or "blind sqli" in tags:
        return "SQLi"
    if "ssti" in tags:
        return "SSTI"
    if "ssrf" in tags:
        return "SSRF"
    if "xxe" in tags:
        return "XXE"
    if "crypto" in tags:
        return "Crypto"
    if "idor" in tags:
        return "IDOR"
    if "path traversal" in tags or "lfi" in tags:
        return "Path/LFI"
    if tags & {"command injection", "blind command injection", "rce", "arbitrary file upload"}:
        return "Command Injection"
    if tags & {"default credentials", "privilege escalation", "jwt"}:
        return "Auth Failures"

    raise ValueError(f"No primary vulnerability category for {machine_id}: {tag_text}")


def load_annotations(csv_path: Path) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    xbow: dict[str, list[int]] = defaultdict(list)
    vulhub: dict[str, list[int]] = defaultdict(list)

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))

    for row in rows:
        machine_id = row["NUMBER MACHINE"].strip()
        count = len(MILESTONE_PATTERN.findall(row["MILESTONE ANNOTATIONS"]))
        if count == 0:
            raise ValueError(f"No milestone headers found for {machine_id}")
        category = primary_category(machine_id, row["TAG"])
        target = vulhub if machine_id.startswith("CVE-") else xbow
        target[category].append(count)

    xbow_count = sum(len(values) for values in xbow.values())
    vulhub_count = sum(len(values) for values in vulhub.values())
    xbow_total = sum(sum(values) for values in xbow.values())
    vulhub_total = sum(sum(values) for values in vulhub.values())

    expected = (50, 8, 223, 28)
    actual = (xbow_count, vulhub_count, xbow_total, vulhub_total)
    if actual != expected:
        raise ValueError(
            "Adjudicated annotation totals do not match the manuscript: "
            f"expected {expected}, found {actual}"
        )

    return xbow, vulhub


def plot_distribution(
    grouped: dict[str, list[int]],
    order: list[str],
    title: str,
    average_label: str,
    output_path: Path,
) -> None:
    categories = [category for category in order if grouped.get(category)]
    all_values = [value for category in categories for value in grouped[category]]
    overall_mean = float(np.mean(all_values))

    fig, ax = plt.subplots(figsize=(12, 5.8), dpi=160)
    colors = plt.cm.Set2(np.linspace(0.05, 0.95, len(categories)))
    category_data = [np.asarray(grouped[category], dtype=float) for category in categories]

    # Violin bodies are meaningful only when a category has a non-zero range.
    # Constant and singleton categories are rendered by the box plot as a
    # horizontal line, matching the representation used in the original paper.
    variable_positions = [
        index
        for index, values in enumerate(category_data, start=1)
        if len(values) > 1 and np.ptp(values) > 0
    ]
    variable_data = [category_data[index - 1] for index in variable_positions]
    if variable_data:
        violin = ax.violinplot(
            variable_data,
            positions=variable_positions,
            widths=0.78,
            showmeans=False,
            showmedians=False,
            showextrema=False,
            bw_method=0.5,
        )
        for body, position in zip(violin["bodies"], variable_positions):
            body.set_facecolor(colors[position - 1])
            body.set_edgecolor("#333333")
            body.set_linewidth(1.1)
            body.set_alpha(0.92)

    boxes = ax.boxplot(
        category_data,
        positions=range(1, len(categories) + 1),
        widths=0.13,
        patch_artist=True,
        showfliers=False,
        whis=(0, 100),
    )
    for box in boxes["boxes"]:
        box.set_facecolor("#3f3f3f")
        box.set_edgecolor("#3f3f3f")
        box.set_linewidth(1.8)
    for whisker in boxes["whiskers"]:
        whisker.set_color("#3f3f3f")
        whisker.set_linewidth(2.1)
    for cap in boxes["caps"]:
        cap.set_color("#3f3f3f")
        cap.set_linewidth(1.6)
    for median in boxes["medians"]:
        median.set_color("white")
        median.set_linewidth(2.0)

    for index, values in enumerate(category_data, start=1):
        if np.ptp(values) == 0:
            ax.hlines(
                values[0],
                index - 0.34,
                index + 0.34,
                color="#3f3f3f",
                linewidth=2.2,
                zorder=4,
            )

    ax.axhline(
        overall_mean,
        color="#d62728",
        linestyle="--",
        linewidth=1.8,
        label=f"{average_label} ({overall_mean:.2f})",
        zorder=1,
    )

    ax.set_title(title, fontsize=17, fontweight="bold", pad=12)
    ax.set_ylabel("Outcome-Oriented Milestones per Challenge", fontsize=12)
    ax.set_xlabel("Vulnerability Category", fontsize=12)
    ax.set_xticks(range(1, len(categories) + 1), categories, rotation=38, ha="right")
    ax.set_yticks(range(min(all_values), max(all_values) + 1))
    ax.set_ylim(min(all_values) - 0.65, max(all_values) + 0.65)
    ax.grid(axis="y", color="#d0d0d0", linewidth=0.8, alpha=0.8)
    ax.set_axisbelow(True)
    ax.legend(loc="upper right", frameon=True, fontsize=10)

    for index, category in enumerate(categories, start=1):
        ax.text(
            index,
            min(all_values) - 0.48,
            f"n={len(grouped[category])}",
            ha="center",
            va="center",
            fontsize=8.5,
            color="#555555",
        )

    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    default_output = (
        repo_root
        / "elsevier_J_Red_MIRROR_INFSOF_D_26_00738_2_Khang_Revision"
        / "Image"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=script_dir / "milestone_after_annotation.csv",
        help="Path to the final adjudicated annotation CSV.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=default_output,
        help="Directory in which the two paper PNG figures are written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    xbow, vulhub = load_annotations(args.input)

    plot_distribution(
        xbow,
        XBOW_ORDER,
        "Outcome-Oriented Milestones by Vulnerability Category (XBOW)",
        "XBOW average",
        args.output_dir / "Subtasks_Analyze_XBOW.png",
    )
    plot_distribution(
        vulhub,
        VULHUB_ORDER,
        "Outcome-Oriented Milestones by Vulnerability Category (Vulhub)",
        "Vulhub average",
        args.output_dir / "Subtasks_Analyze_Vulhub.png",
    )

    print("Generated milestone figures from the final adjudicated annotations:")
    print(f"  XBOW:   50 challenges, 223 milestones, mean {223 / 50:.2f}")
    print(f"  Vulhub:  8 scenarios,  28 milestones, mean {28 / 8:.2f}")


if __name__ == "__main__":
    main()
