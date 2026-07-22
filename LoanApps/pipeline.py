#!/usr/bin/env python3
"""
LoanWatch Pipeline Orchestrator
================================
Automates the full compliance audit pipeline for loan app analysis.

Stages:
  0. policy      - LLM policy-to-permission mapping   (policy_extractor.py + Groq API)
  1. permission  - Manifest permission analysis       (analyzeapk.py)
  2. filter      - Filter LoanWatch violations        (built-in)
  3. copy        - Copy violating APKs                (copyviolatingapps.py)
  4. api         - Sensitive API analysis             (apianalysis.py)
  5. flowdroid   - FlowDroid data flow analysis       (dataflowanalysis.sh)
  6. parse       - Parse FlowDroid XML results        (dataflowanalysisresultparser.py)

Usage:
  python3 pipeline.py                                    # Run all stages
  python3 pipeline.py --from api                         # Start from stage 'api'
  python3 pipeline.py --only filter                      # Run only the filter stage
  python3 pipeline.py --skip flowdroid                   # Run all except flowdroid
  python3 pipeline.py --list                             # List available stages
  GROQ_API_KEY=gsk_... python3 pipeline.py               # Full run including policy stage
"""

import os
import sys
import csv
import subprocess
import logging
import argparse
from datetime import datetime
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR      = Path("/data/olawalea/LoanApps")
RESULTS_DIR   = BASE_DIR / "Results"
SENSITIVE_DIR = BASE_DIR / "SensitiveAPIAnalysis"

PERM_CSV      = BASE_DIR / "permission_reporttest.csv"
VIOLATING_CSV = RESULTS_DIR / "violating_loanwatch.csv"
PERM_SETS_PY  = BASE_DIR / "permission_sets.py"

# LoanWatch permission set — must match PERMISSIONS in analyzeapk.py
LOANWATCH_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_SMS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.ACCESS_FINE_LOCATION",
]

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = BASE_DIR / "pipeline.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def run_cmd(cmd, cwd=None, label=""):
    """Run a shell command, stream output live, raise on non-zero exit."""
    log.info(f"Running [{label}]: {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, cwd=str(cwd or BASE_DIR))
    if result.returncode != 0:
        raise RuntimeError(
            f"Stage '{label}' failed with exit code {result.returncode}"
        )

def require_file(path, stage_hint):
    if not Path(path).exists():
        raise FileNotFoundError(
            f"Required file not found: {path}\n"
            f"  → Run the '{stage_hint}' stage first."
        )

# ─── Stage functions ──────────────────────────────────────────────────────────

def stage_policy():
    """
    Run policy_extractor.py to query the Groq LLM on each country's regulatory
    PDF and extract prohibited Android permissions.
    Requires GROQ_API_KEY environment variable (or --groq-key CLI arg).
    Outputs: LoanPolicyandlist/extracted_permissions.json + permission_sets.py
    """
    script = BASE_DIR / "policy_extractor.py"
    require_file(script, "— ensure policy_extractor.py exists in LoanApps/")

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "GROQ_API_KEY is not set.\n"
            "  Export it before running:  export GROQ_API_KEY='gsk_...'\n"
            "  Or skip this stage:        python3 pipeline.py --from permission"
        )

    run_cmd(
        ["python3", str(script)],
        cwd=BASE_DIR,
        label="policy",
    )

    if PERM_SETS_PY.exists():
        log.info(f"Policy extraction done → {PERM_SETS_PY}")
    else:
        log.warning("policy_extractor.py ran but permission_sets.py was not produced.")


def stage_permission():
    """
    Run analyzeapk.py to scan all APKs in LoanApps/ and produce
    permission_reporttest.csv with per-app permission flags and violation booleans.
    """
    run_cmd(
        ["python3", str(BASE_DIR / "analyzeapk.py")],
        cwd=BASE_DIR,
        label="permission",
    )
    if not PERM_CSV.exists():
        raise FileNotFoundError(
            f"analyzeapk.py finished but expected output not found: {PERM_CSV}"
        )
    rows = sum(1 for _ in open(PERM_CSV)) - 1
    log.info(f"Permission analysis done — {rows} apps → {PERM_CSV}")


def stage_filter():
    """
    Read permission_reporttest.csv, keep rows where ViolateLoanWatch == TRUE,
    and write Results/violating_loanwatch.csv with a ViolatingPermissions column.
    This is the glue step between analyzeapk.py and the rest of the pipeline.
    """
    require_file(PERM_CSV, "permission")
    RESULTS_DIR.mkdir(exist_ok=True)

    written = 0
    fieldnames = ["App Name", "Package Name", "Country/Classification", "ViolatingPermissions"]

    with open(PERM_CSV, newline="", encoding="utf-8") as fin, \
         open(VIOLATING_CSV, "w", newline="", encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if row.get("ViolateLoanWatch", "").strip().upper() != "TRUE":
                continue

            # Collect which specific LoanWatch permissions the app holds
            violating = [p for p in LOANWATCH_PERMISSIONS if row.get(p, "").strip() == "Yes"]
            writer.writerow({
                "App Name":               row["App Name"],
                "Package Name":           row["Package Name"],
                "Country/Classification": row["Country/Classification"],
                "ViolatingPermissions":   ", ".join(violating),
            })
            written += 1

    log.info(f"Filter done — {written} LoanWatch-violating apps → {VIOLATING_CSV}")


def stage_copy():
    """
    Run copyviolatingapps.py to scan all country folders, match APKs by
    package name from violating_loanwatch.csv, and copy them into
    SensitiveAPIAnalysis/{Country}{Status}/ for deeper analysis.
    """
    require_file(VIOLATING_CSV, "filter")
    run_cmd(
        ["python3", str(BASE_DIR / "copyviolatingapps.py")],
        cwd=BASE_DIR,
        label="copy",
    )
    if not SENSITIVE_DIR.exists():
        raise FileNotFoundError(
            f"copyviolatingapps.py finished but SensitiveAPIAnalysis/ not found: {SENSITIVE_DIR}"
        )
    apk_count = sum(
        1 for p in SENSITIVE_DIR.rglob("*.apk") if p.parent != SENSITIVE_DIR / "Results"
    )
    log.info(f"Copy done — {apk_count} APKs staged in {SENSITIVE_DIR}")


def stage_api():
    """
    Run apianalysis.py to perform Androguard bytecode analysis on the staged
    APKs, confirming which sensitive APIs are actually invoked.
    Output: Results/api_analysis_results.csv
    """
    require_file(VIOLATING_CSV, "filter")
    if not SENSITIVE_DIR.exists():
        raise FileNotFoundError(
            f"SensitiveAPIAnalysis/ not found. Run the 'copy' stage first."
        )
    run_cmd(
        ["python3", str(BASE_DIR / "apianalysis.py")],
        cwd=BASE_DIR,
        label="api",
    )
    out = RESULTS_DIR / "api_analysis_results.csv"
    if out.exists():
        rows = sum(1 for _ in open(out)) - 1
        log.info(f"API analysis done — {rows} apps analysed → {out}")
    else:
        log.warning(f"apianalysis.py completed but output CSV not found at {out}")


def stage_flowdroid():
    """
    Run dataflowanalysis.sh, which invokes FlowDroid on every APK in
    SensitiveAPIAnalysis/, using sourcesandsinks.txt as source/sink definitions.
    Output: SensitiveAPIAnalysis/Results/{Country}/<app>.xml
    """
    script = BASE_DIR / "dataflowanalysis.sh"
    require_file(script, "— ensure dataflowanalysis.sh exists in LoanApps/")
    if not SENSITIVE_DIR.exists():
        raise FileNotFoundError(
            f"SensitiveAPIAnalysis/ not found. Run the 'copy' stage first."
        )
    run_cmd(["bash", str(script)], cwd=BASE_DIR, label="flowdroid")
    xml_count = sum(1 for _ in SENSITIVE_DIR.rglob("*.xml"))
    log.info(f"FlowDroid done — {xml_count} XML result files produced")


def stage_parse():
    """
    Run dataflowanalysisresultparser.py to read FlowDroid XML outputs and
    produce source_leak_summary.csv, source_counts.txt, and per-APK TXT files.
    """
    xml_files = list(SENSITIVE_DIR.rglob("*.xml"))
    if not xml_files:
        raise FileNotFoundError(
            "No FlowDroid XML results found in SensitiveAPIAnalysis/. "
            "Run the 'flowdroid' stage first."
        )
    run_cmd(
        ["python3", str(BASE_DIR / "dataflowanalysisresultparser.py")],
        cwd=BASE_DIR,
        label="parse",
    )
    summary = SENSITIVE_DIR / "Results" / "source_leak_summary.csv"
    if summary.exists():
        rows = sum(1 for _ in open(summary)) - 1
        log.info(f"Parse done — {rows} APKs in leak summary → {summary}")
    else:
        log.warning(f"Parser completed but summary CSV not found at {summary}")


# ─── Stage registry ───────────────────────────────────────────────────────────

STAGES = ["policy", "permission", "filter", "copy", "api", "flowdroid", "parse"]

STAGE_FNS = {
    "policy":     stage_policy,
    "permission": stage_permission,
    "filter":     stage_filter,
    "copy":       stage_copy,
    "api":        stage_api,
    "flowdroid":  stage_flowdroid,
    "parse":      stage_parse,
}

STAGE_DESC = {
    "policy":     "LLM policy-to-permission mapping via Groq API (policy_extractor.py)",
    "permission": "Manifest permission analysis (analyzeapk.py)",
    "filter":     "Filter LoanWatch violations → violating_loanwatch.csv",
    "copy":       "Copy violating APKs to SensitiveAPIAnalysis/ (copyviolatingapps.py)",
    "api":        "Sensitive API bytecode analysis (apianalysis.py)",
    "flowdroid":  "FlowDroid taint analysis (dataflowanalysis.sh)",
    "parse":      "Parse FlowDroid XML results (dataflowanalysisresultparser.py)",
}

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LoanWatch Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--from", dest="from_stage", metavar="STAGE", choices=STAGES,
        help="Start pipeline from this stage (inclusive)",
    )
    group.add_argument(
        "--only", dest="only_stage", metavar="STAGE", choices=STAGES,
        help="Run only this single stage",
    )
    group.add_argument(
        "--skip", dest="skip_stage", metavar="STAGE", choices=STAGES,
        help="Run all stages except this one",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available stages and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable pipeline stages (run in order):\n")
        for i, s in enumerate(STAGES, 1):
            print(f"  {i}. {s:<12} {STAGE_DESC[s]}")
        print()
        return

    if args.only_stage:
        to_run = [args.only_stage]
    elif args.from_stage:
        to_run = STAGES[STAGES.index(args.from_stage):]
    elif args.skip_stage:
        to_run = [s for s in STAGES if s != args.skip_stage]
    else:
        to_run = STAGES

    log.info("=" * 70)
    log.info("LoanWatch Pipeline starting")
    log.info(f"Stages to run: {to_run}")
    log.info(f"Timestamp: {datetime.now().isoformat()}")
    log.info("=" * 70)

    for stage in to_run:
        log.info(f"\n{'─'*70}")
        log.info(f"  STAGE: {stage.upper()} — {STAGE_DESC[stage]}")
        log.info(f"{'─'*70}")
        try:
            STAGE_FNS[stage]()
            log.info(f"  ✓ Stage '{stage}' completed successfully\n")
        except Exception as e:
            log.error(f"  ✗ Stage '{stage}' FAILED: {e}")
            log.error(f"  Fix the error above, then re-run with:  --from {stage}")
            sys.exit(1)

    log.info("=" * 70)
    log.info("Pipeline completed successfully.")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
