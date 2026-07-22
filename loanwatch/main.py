#!/usr/bin/env python3
"""
LoanWatch Pipeline
==================
Automated regulatory compliance and data-exfiltration analysis for loan APKs.

Stages:
  1. PDF policy  →  LLM  →  prohibited permissions
  2. Manifest audit  →  VIOLATING check
  3. LLM maps permissions  →  Android API identifiers
  4. Androguard  →  source classes/methods
  5. FlowDroid taint trace  →  confirmed paths  (optional)
  6. LLM  →  Frida instrumentation script

Usage:
  python3 main.py --apk easycash.apk --policy policy.pdf
  python3 main.py --apk easycash.apk --policy policy.pdf --flowdroid path/to/flowdroid.jar
  python3 main.py --apk easycash.apk --policy policy.pdf --out report.json --quiet
"""
import argparse
import json
import os
import sys
import time

import stage1_policy
import stage2_audit
import stage3_api_map
import stage4_static
import stage5_taint
import stage6_frida


DIVIDER = "─" * 70


def banner(text: str):
    print(f"\n{DIVIDER}")
    print(f"  {text}")
    print(DIVIDER)


def main():
    parser = argparse.ArgumentParser(
        prog="loanwatch",
        description="LoanWatch: Regulatory compliance + taint analysis for loan APKs",
    )
    parser.add_argument("--apk",       required=True, metavar="PATH",
                        help="Path to the APK file")
    parser.add_argument("--policy",    required=True, metavar="PDF",
                        help="Path to the regulatory policy PDF")
    parser.add_argument("--clause",    type=int, default=15, metavar="N",
                        help="Clause number to analyse (default: 15)")
    parser.add_argument("--groq-key",  metavar="API_KEY",
                        help="Groq API key (or set GROQ_API_KEY env var)")
    parser.add_argument("--flowdroid", metavar="JAR",
                        default=os.path.join(os.path.dirname(__file__), "lib", "flowdroid.jar"),
                        help="Path to FlowDroid JAR (default: lib/flowdroid.jar)")
    parser.add_argument("--platforms", metavar="DIR",
                        default=os.path.expanduser("~/Library/Android/sdk/platforms"),
                        help="Android platforms dir (default: ~/Library/Android/sdk/platforms)")
    parser.add_argument("--out",       metavar="JSON_FILE",
                        help="Save full report to this JSON file")
    parser.add_argument("--frida-out", metavar="JS_FILE",
                        help="Save generated Frida script to this file")
    parser.add_argument("--quiet",     action="store_true",
                        help="Suppress per-stage output")
    args = parser.parse_args()

    # ── API key ────────────────────────────────────────────────────────────────
    api_key = args.groq_key or os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        print("ERROR: Groq API key required.\n"
              "  Set GROQ_API_KEY env var  or  use --groq-key gsk_...",
              file=sys.stderr)
        sys.exit(1)

    # ── File checks ────────────────────────────────────────────────────────────
    for label, path in [("APK", args.apk), ("Policy PDF", args.policy)]:
        if not os.path.exists(path):
            print(f"ERROR: {label} not found: {path}", file=sys.stderr)
            sys.exit(1)

    verbose = not args.quiet
    t_total = time.time()
    report  = {}

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 1 — Policy extraction
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 1 — Policy PDF → Prohibited permissions")
    t0 = time.time()
    s1 = stage1_policy.run(args.policy, api_key, args.clause, verbose)
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
        time.sleep(3)
    report["stage1"] = s1

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 2 — Manifest audit
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 2 — Manifest Audit")
    t0 = time.time()
    s2 = stage2_audit.run(args.apk, s1["permissions"], verbose)
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
        time.sleep(3)
    report["stage2"] = s2

    if not s2["violating"]:
        print("\n✓ App is COMPLIANT — no prohibited permissions declared.")
        if args.out:
            with open(args.out, "w") as f:
                json.dump(report, f, indent=2)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 3 — Permission → API identifiers
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 3 — Permissions → Android API Identifiers")
    t0 = time.time()
    # Only map permissions that were actually matched in the manifest
    violated = [p.replace("android.permission.", "").upper()
                for p in s2["matched_permissions"]]
    s3 = stage3_api_map.run(violated, s1["prohibited_data"], api_key, verbose)
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
        time.sleep(3)
    report["stage3"] = s3

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 4 — Static source discovery
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 4 — Static Analysis (Androguard)")
    t0 = time.time()
    s4 = stage4_static.run(args.apk, s3["api_targets"], verbose)
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
        time.sleep(3)
    report["stage4"] = s4

    if not s4["sources"]:
        print("\n[!] No API call sites found in bytecode — "
              "data access may be through native code or reflection.")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 5 — FlowDroid taint analysis
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 5 — Taint Analysis (FlowDroid)")
    t0 = time.time()
    s5 = stage5_taint.run(
        args.apk,
        s4["sources"],
        flowdroid_jar=args.flowdroid or "",
        platforms_dir=args.platforms or "",
        verbose=verbose,
    )
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
        time.sleep(3)
    report["stage5"] = s5

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 6 — Frida script generation
    # ══════════════════════════════════════════════════════════════════════════
    if verbose:
        banner("Stage 6 — Frida Script Generation")
    t0 = time.time()
    s6 = stage6_frida.run(
        s5["confirmed_sources"],
        s2["app_name"],
        s2["package"],
        api_key,
        verbose,
    )
    if verbose:
        print(f"  [done in {time.time()-t0:.1f}s]")
    report["stage6"] = {"hooked_methods": s6["hooked_methods"]}

    # ══════════════════════════════════════════════════════════════════════════
    # Print summary
    # ══════════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t_total
    print(f"\n{'═'*70}")
    print(f"  LOANWATCH REPORT  —  {s2['app_name']}  ({s2['package']})")
    print(f"{'═'*70}")
    print(f"  Compliance status : VIOLATING")
    print(f"  Prohibited perms  : {', '.join(s2['matched_permissions'])}")
    print(f"  Source methods    : {len(s4['sources'])}")
    print(f"  FlowDroid ran     : {'Yes' if s5['ran_flowdroid'] else 'No (static only)'}")
    print(f"  Confirmed paths   : {len(s5['confirmed_sources'])}")
    print(f"  Frida hooks       : {len(s6['hooked_methods'])}")
    print(f"  Total time        : {elapsed:.1f}s")
    print(f"{'═'*70}\n")

    # Print Frida script
    print("GENERATED FRIDA SCRIPT")
    print("─" * 70)
    print(s6["frida_script"])
    print()

    # ── Save outputs ───────────────────────────────────────────────────────────
    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Full report saved to {args.out}")

    frida_path = args.frida_out or (
        os.path.splitext(os.path.basename(args.apk))[0] + "_frida.js"
    )
    with open(frida_path, "w") as f:
        f.write(s6["frida_script"])
    print(f"[*] Frida script saved to {frida_path}")


if __name__ == "__main__":
    main()
