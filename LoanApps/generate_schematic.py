#!/usr/bin/env python3
"""
Generate a visual schematic of the LoanWatch pipeline.
Output: LoanApps/Results/loanwatch_pipeline_schematic.png
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "Results", "loanwatch_pipeline_schematic.png")
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

# ─── Colour palette ───────────────────────────────────────────────────────────
C = {
    "input":      "#D6EAF8",   # light blue  – input data
    "stage":      "#D5F5E3",   # light green – pipeline stages
    "output":     "#FEF9E7",   # light yellow – outputs / artefacts
    "manual":     "#FADBD8",   # light red   – manual / external steps
    "tool":       "#EBE9FC",   # light purple – external tools
    "border":     "#2C3E50",
    "arrow":      "#2C3E50",
    "text":       "#1A252F",
    "label":      "#555555",
    "title_bg":   "#2C3E50",
    "title_fg":   "white",
}

# ─── Helper: draw a rounded box ───────────────────────────────────────────────

def box(ax, x, y, w, h, text, subtext="", color=C["stage"], fontsize=8.5,
        subfontsize=7, bold=False):
    patch = FancyBboxPatch(
        (x - w / 2, y - h / 2), w, h,
        boxstyle="round,pad=0.02",
        facecolor=color, edgecolor=C["border"], linewidth=1.0,
        zorder=3,
    )
    ax.add_patch(patch)
    weight = "bold" if bold else "normal"
    ax.text(x, y + (0.08 if subtext else 0), text,
            ha="center", va="center", fontsize=fontsize,
            color=C["text"], fontweight=weight, zorder=4, wrap=True,
            multialignment="center")
    if subtext:
        ax.text(x, y - 0.18, subtext,
                ha="center", va="center", fontsize=subfontsize,
                color=C["label"], style="italic", zorder=4,
                multialignment="center")

def arrow(ax, x1, y1, x2, y2, label="", color=C["arrow"]):
    ax.annotate("",
                xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=1.4, mutation_scale=12),
                zorder=5)
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx + 0.06, my, label, fontsize=6.5, color=C["label"],
                ha="left", va="center", style="italic", zorder=6)

def bracket_arrow(ax, x1, y1, x2, y2, mid_x, color=C["arrow"]):
    """L-shaped arrow via a waypoint."""
    ax.annotate("",
                xy=(mid_x, y1), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-", color=color, lw=1.2), zorder=5)
    ax.annotate("",
                xy=(x2, y2), xytext=(mid_x, y1),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=1.2, mutation_scale=11), zorder=5)

# ─── Figure setup ─────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(14, 18))
ax.set_xlim(0, 10)
ax.set_ylim(0, 18)
ax.axis("off")

# Title bar
title_rect = FancyBboxPatch((0.1, 16.9), 9.8, 0.9,
                             boxstyle="round,pad=0.04",
                             facecolor=C["title_bg"], edgecolor="none", zorder=2)
ax.add_patch(title_rect)
ax.text(5, 17.35, "LoanWatch  —  Automated Compliance Audit Pipeline",
        ha="center", va="center", fontsize=13, fontweight="bold",
        color=C["title_fg"], zorder=3)

# ══════════════════════════════════════════════════════════════════════════════
#  INPUTS  (top row)
# ══════════════════════════════════════════════════════════════════════════════
# Policy PDFs
box(ax, 2.5, 15.9, 3.0, 0.7,
    "Policy PDFs  (manual collection)",
    "LoanPolicyandlist/",
    color=C["manual"], fontsize=8, bold=False)

# APK folders
box(ax, 7.0, 15.9, 3.0, 0.7,
    "APK Folders  (manual collection)",
    "Nigeria*/Kenya*/Pakistan*/…",
    color=C["manual"], fontsize=8, bold=False)

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — Policy-to-Permission Mapping
# ══════════════════════════════════════════════════════════════════════════════
arrow(ax, 2.5, 15.55, 2.5, 14.85)

box(ax, 2.5, 14.45, 3.2, 0.75,
    "Phase 1 · Policy-to-Permission Mapping",
    "GPT-4o Mini + Claude Sonnet 4  (LLM)",
    color=C["tool"], fontsize=8, bold=True)

# output label
ax.text(2.5, 13.85, "Country prohibited-permission sets\n(hardcoded in analyzeapk.py)",
        ha="center", va="top", fontsize=6.8, color=C["label"], style="italic")

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Static Analysis
# ══════════════════════════════════════════════════════════════════════════════

# Section label
ax.text(0.25, 13.3, "STATIC ANALYSIS", fontsize=8, fontweight="bold",
        color="#1A5276", va="center", rotation=90)
ax.plot([0.55, 0.55], [10.1, 13.6], color="#1A5276", lw=1.2, ls="--")

# --- Stage 1: Permission Analysis ---
# APK folder arrow into stage
arrow(ax, 7.0, 15.55, 7.0, 13.1)
# Policy sets arrow into stage
arrow(ax, 2.5, 13.55, 4.8, 12.8)

box(ax, 5.0, 12.65, 3.6, 0.75,
    "Stage 1 · Permission Analysis",
    "analyzeapk.py  (Androguard)",
    color=C["stage"], fontsize=8.5, bold=True)

arrow(ax, 5.0, 12.27, 5.0, 11.7,
      label="permission_reporttest.csv")

# --- Stage 2: Filter Violators ---
box(ax, 5.0, 11.35, 3.6, 0.65,
    "Stage 2 · Filter LoanWatch Violators",
    "pipeline.py  (built-in step)",
    color=C["stage"], fontsize=8.5, bold=True)

arrow(ax, 5.0, 11.02, 5.0, 10.45,
      label="violating_loanwatch.csv")

# --- Stage 3: Copy Violating APKs ---
box(ax, 5.0, 10.1, 3.6, 0.65,
    "Stage 3 · Copy Violating APKs",
    "copyviolatingapps.py",
    color=C["stage"], fontsize=8.5, bold=True)

arrow(ax, 5.0, 9.77, 5.0, 9.2,
      label="SensitiveAPIAnalysis/{Country}/")

# Staging box
box(ax, 5.0, 8.9, 3.6, 0.55,
    "Staged APKs  (flagged apps only)",
    "SensitiveAPIAnalysis/NigeriaApproved/ …",
    color=C["output"], fontsize=7.5)

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 continues — API Analysis + FlowDroid (parallel branches)
# ══════════════════════════════════════════════════════════════════════════════

# Fork left → API Analysis
bracket_arrow(ax, 5.0, 8.62, 2.5, 8.0, mid_x=2.5)
# Fork right → FlowDroid
bracket_arrow(ax, 5.0, 8.62, 7.5, 8.0, mid_x=7.5)

# --- Stage 4: Sensitive API Analysis ---
box(ax, 2.5, 7.65, 3.4, 0.65,
    "Stage 4 · Sensitive API Analysis",
    "apianalysis.py  (Androguard bytecode)",
    color=C["stage"], fontsize=8.5, bold=True)

arrow(ax, 2.5, 7.32, 2.5, 6.75,
      label="api_analysis_results.csv")

box(ax, 2.5, 6.5, 3.0, 0.45,
    "API call evidence per app",
    "Results/api_analysis_results.csv",
    color=C["output"], fontsize=7.5)

# --- Stage 5: FlowDroid ---
box(ax, 7.5, 7.65, 3.4, 0.65,
    "Stage 5 · Data Flow Analysis",
    "dataflowanalysis.sh  (FlowDroid)",
    color=C["tool"], fontsize=8.5, bold=True)

# sources & sinks
box(ax, 7.5, 8.7, 2.2, 0.45,
    "sourcesandsinks.txt",
    "sources / sinks config",
    color=C["input"], fontsize=7)
arrow(ax, 7.5, 8.47, 7.5, 8.0)

arrow(ax, 7.5, 7.32, 7.5, 6.75,
      label="*.xml per app")

box(ax, 7.5, 6.5, 3.0, 0.45,
    "FlowDroid XML results",
    "SensitiveAPIAnalysis/Results/{Country}/",
    color=C["output"], fontsize=7.5)

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Stage 6: Parse Results
# ══════════════════════════════════════════════════════════════════════════════

# Merge branches
arrow(ax, 2.5, 6.27, 2.5, 5.5)
bracket_arrow(ax, 2.5, 5.5, 5.0, 5.18, mid_x=5.0)
arrow(ax, 7.5, 6.27, 7.5, 5.5)
bracket_arrow(ax, 7.5, 5.5, 5.0, 5.18, mid_x=5.0)

box(ax, 5.0, 4.85, 3.6, 0.65,
    "Stage 6 · Parse FlowDroid Results",
    "dataflowanalysisresultparser.py",
    color=C["stage"], fontsize=8.5, bold=True)

arrow(ax, 5.0, 4.52, 5.0, 3.85)

# Outputs
box(ax, 5.0, 3.55, 4.2, 0.55,
    "source_leak_summary.csv  ·  source_counts.txt  ·  per-APK TXT",
    "SensitiveAPIAnalysis/Results/",
    color=C["output"], fontsize=7.5)

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — Dynamic Analysis
# ══════════════════════════════════════════════════════════════════════════════

ax.text(0.25, 2.7, "DYNAMIC ANALYSIS", fontsize=8, fontweight="bold",
        color="#6E2FA1", va="center", rotation=90)
ax.plot([0.55, 0.55], [1.3, 3.2], color="#6E2FA1", lw=1.2, ls="--")

arrow(ax, 5.0, 3.27, 5.0, 2.75, label="high-risk apps flagged")

box(ax, 5.0, 2.4, 4.4, 0.65,
    "Phase 3 · Dynamic Analysis  (semi-automated)",
    "Frida instrumentation  ·  Nexus 6P device  ·  ADB",
    color=C["tool"], fontsize=8.5, bold=True)

arrow(ax, 5.0, 2.07, 5.0, 1.5)

box(ax, 5.0, 1.2, 4.2, 0.55,
    "Runtime evidence  ·  API call logs  ·  network endpoints",
    "pre-registration interaction scope",
    color=C["output"], fontsize=7.5)

# ══════════════════════════════════════════════════════════════════════════════
#  Legend
# ══════════════════════════════════════════════════════════════════════════════
legend_items = [
    (C["manual"], "Manual / collection step"),
    (C["stage"],  "Automated pipeline stage"),
    (C["tool"],   "External tool / LLM"),
    (C["output"], "Output artefact"),
    (C["input"],  "Config / input file"),
]
lx, ly = 0.6, 0.72
for i, (clr, lbl) in enumerate(legend_items):
    px = lx + i * 1.88
    patch = FancyBboxPatch((px, ly), 0.28, 0.22,
                            boxstyle="round,pad=0.02",
                            facecolor=clr, edgecolor=C["border"], linewidth=0.8, zorder=3)
    ax.add_patch(patch)
    ax.text(px + 0.33, ly + 0.11, lbl, fontsize=6.5, va="center", color=C["text"])

ax.text(5.0, 0.2,
        "pipeline.py  orchestrates stages 1–6 automatically  ·  "
        "run:  python3 pipeline.py  [--from STAGE | --only STAGE | --skip STAGE]",
        ha="center", va="center", fontsize=7, color="#555555", style="italic")

plt.tight_layout(pad=0.3)
plt.savefig(OUTPUT_PATH, dpi=180, bbox_inches="tight")
print(f"Schematic saved → {OUTPUT_PATH}")
