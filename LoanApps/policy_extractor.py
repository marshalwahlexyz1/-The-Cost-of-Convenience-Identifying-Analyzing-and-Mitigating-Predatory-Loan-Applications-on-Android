#!/usr/bin/env python3
"""
LoanWatch · Phase 1: Policy-to-Permission Mapping
===================================================
Uses the Groq API (LLM) to extract prohibited Android permissions from
national regulatory policy PDFs, then writes the results to:
  - LoanPolicyandlist/extracted_permissions.json   (structured output)
  - permission_sets.py                             (drop-in config for analyzeapk.py)

Usage:
  export GROQ_API_KEY="gsk_..."
  python3 policy_extractor.py

  # Or pass the key directly:
  python3 policy_extractor.py --api-key gsk_...

  # Process a single country only:
  python3 policy_extractor.py --country Nigeria

  # List available models:
  python3 policy_extractor.py --list-models
"""

import os
import re
import json
import logging
import argparse
from pathlib import Path

import PyPDF2
from groq import Groq

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
POLICY_DIR  = BASE_DIR / "LoanPolicyandlist"
OUTPUT_JSON = POLICY_DIR / "extracted_permissions.json"
OUTPUT_PY   = BASE_DIR  / "permission_sets.py"

# ─── Country → policy PDF mapping ────────────────────────────────────────────
# Map each country to the PDF filename(s) in LoanPolicyandlist/ that contain
# the actual regulatory/guideline text (NOT app-list PDFs).
# Add or update entries here when you add new policy documents.
POLICY_MAP = {
    "India": [
        "GUIDELINESDIGITALLENDINGD5C35A71D8124A0E92AEB940A7D25BB3.pdf",
    ],
    "Nigeria": [
        # FCCPC Digital Money Lenders guidelines — add the filename here
        # e.g. "FCCPC_DML_Guidelines_2022.pdf"
    ],
    "Kenya": [
        # e.g. "CBK_Digital_Credit_Providers_Regulations_2022.pdf"
    ],
    "Pakistan": [
        # e.g. "SECP_Digital_Lending_Policy_2022.pdf"
    ],
    "Philippines": [
        "Digital Lending in the Philippines- Maximizing Opportunities and Mitigating Risks for MSME Finance.pdf",
    ],
    "Indonesia": [
        # e.g. "OJK_POJK_10_2022.pdf"
    ],
    "Thailand": [
        # e.g. "BOT_Digital_Lending_Circular.pdf"
    ],
}

# ─── Groq model to use ────────────────────────────────────────────────────────
DEFAULT_MODEL = "llama-3.3-70b-versatile"   # best accuracy on Groq as of 2025
FALLBACK_MODEL = "mixtral-8x7b-32768"       # large context window

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "policy_extractor.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── All known AOSP permissions (for validation) ──────────────────────────────
KNOWN_AOSP_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_BIOMETRIC",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
}

# ─── Prompt template ──────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert in Android mobile security and data-privacy law.
Your task is to analyse regulatory or policy documents governing digital/loan apps
and map the data-access restrictions they describe to concrete Android AOSP permissions.

Respond ONLY with valid JSON in exactly this schema — no prose, no markdown fences:
{
  "country": "<country name>",
  "unconditional": ["android.permission.X", ...],
  "conditional":   ["android.permission.Y", ...]
}

Definitions:
- "unconditional": permissions the regulation bans REGARDLESS of user consent or context.
- "conditional":   permissions the regulation restricts but MAY allow under specific conditions
                   (e.g. only during KYC, only with explicit consent, only during onboarding).
- Use only real android.permission.* strings from AOSP — no invented permissions.
- If no permissions are prohibited, return empty lists."""

USER_PROMPT_TEMPLATE = """Country: {country}

Regulatory document text (may be truncated to fit context):
---
{policy_text}
---

Extract all Android permissions that loan apps are prohibited or restricted from
accessing under this regulation. Classify each as unconditional or conditional."""

# ─── PDF extraction ───────────────────────────────────────────────────────────

def extract_pdf_text(pdf_path: Path, max_chars: int = 28_000) -> str:
    """Extract plain text from a PDF, up to max_chars to stay within LLM context."""
    try:
        with open(pdf_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            pages = [reader.pages[i].extract_text() or "" for i in range(len(reader.pages))]
        text = "\n".join(pages)
        if len(text) > max_chars:
            log.warning(f"  PDF text truncated from {len(text)} to {max_chars} chars")
            text = text[:max_chars]
        return text.strip()
    except Exception as e:
        raise RuntimeError(f"Could not read PDF {pdf_path.name}: {e}") from e

# ─── LLM call ─────────────────────────────────────────────────────────────────

def query_llm(client: Groq, country: str, policy_text: str, model: str) -> dict:
    """Send the policy text to the Groq LLM and parse the JSON response."""
    user_msg = USER_PROMPT_TEMPLATE.format(country=country, policy_text=policy_text)

    log.info(f"  Querying {model} for {country} ({len(policy_text)} chars of policy text)…")

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        temperature=0.0,      # deterministic
        max_tokens=1024,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()
    log.debug(f"  Raw LLM response: {raw}")

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON for {country}: {e}\nRaw: {raw}") from e

    # Validate and filter to known AOSP permissions only
    for key in ("unconditional", "conditional"):
        original = result.get(key, [])
        valid    = [p for p in original if p in KNOWN_AOSP_PERMISSIONS]
        unknown  = [p for p in original if p not in KNOWN_AOSP_PERMISSIONS]
        if unknown:
            log.warning(f"  [{country}] Dropping unknown permissions from '{key}': {unknown}")
        result[key] = valid

    result["country"] = country
    return result

# ─── Output writers ───────────────────────────────────────────────────────────

def write_json(results: list[dict]):
    """Write full structured output to extracted_permissions.json."""
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info(f"JSON output → {OUTPUT_JSON}")


def write_python_config(results: list[dict]):
    """
    Write permission_sets.py — a drop-in Python config that replaces the
    hardcoded COUNTRY_SETS dict in analyzeapk.py.
    Import it as:  from permission_sets import COUNTRY_SETS, GOOGLE_PERMS, LOANWATCH_PERMS
    """
    lines = [
        "# AUTO-GENERATED by policy_extractor.py — do not edit by hand.",
        "# Re-run policy_extractor.py to regenerate.",
        "",
        "# Country-specific unconditional prohibited permissions",
        "COUNTRY_SETS = {",
    ]
    for r in results:
        country = r["country"]
        perms   = r.get("unconditional", [])
        perm_str = ",\n        ".join(f'"{p}"' for p in sorted(perms))
        lines.append(f'    "{country}": {{')
        if perm_str:
            lines.append(f"        {perm_str},")
        lines.append("    },")
    lines.append("}")

    # Google's FSP prohibited set (static — from Google policy)
    lines += [
        "",
        "# Google Financial Services Policy prohibited permissions (static)",
        "GOOGLE_PERMS = {",
        '    "android.permission.READ_EXTERNAL_STORAGE",',
        '    "android.permission.READ_MEDIA_IMAGES",',
        '    "android.permission.READ_CONTACTS",',
        '    "android.permission.ACCESS_FINE_LOCATION",',
        '    "android.permission.READ_PHONE_NUMBERS",',
        '    "android.permission.READ_MEDIA_VIDEO",',
        '    "android.permission.QUERY_ALL_PACKAGES",',
        '    "android.permission.WRITE_EXTERNAL_STORAGE",',
        "}",
        "",
        "# LoanWatch set = Google UNION of all country unconditional sets",
        "LOANWATCH_PERMS = GOOGLE_PERMS.copy()",
        "for _perms in COUNTRY_SETS.values():",
        "    LOANWATCH_PERMS.update(_perms)",
        "",
        "# Conditional permissions (context-dependent, for dynamic analysis)",
        "CONDITIONAL_SETS = {",
    ]
    for r in results:
        country = r["country"]
        perms   = r.get("conditional", [])
        perm_str = ",\n        ".join(f'"{p}"' for p in sorted(perms))
        lines.append(f'    "{country}": {{')
        if perm_str:
            lines.append(f"        {perm_str},")
        lines.append("    },")
    lines.append("}")

    with open(OUTPUT_PY, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log.info(f"Python config → {OUTPUT_PY}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LoanWatch Policy-to-Permission Extractor")
    parser.add_argument("--api-key",    metavar="KEY",
                        help="Groq API key (or set GROQ_API_KEY env var)")
    parser.add_argument("--model",      default=DEFAULT_MODEL,
                        help=f"Groq model to use (default: {DEFAULT_MODEL})")
    parser.add_argument("--country",    metavar="NAME",
                        help="Process only this country (default: all)")
    parser.add_argument("--list-models", action="store_true",
                        help="Print recommended Groq models and exit")
    args = parser.parse_args()

    if args.list_models:
        print("\nRecommended Groq models for policy extraction:\n")
        print(f"  {DEFAULT_MODEL:<35} ← default, best accuracy")
        print(f"  {FALLBACK_MODEL:<35} ← large context window (32k tokens)")
        print("  llama-3.1-8b-instant               ← fast, lower accuracy\n")
        return

    api_key = args.api_key or os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        parser.error(
            "Groq API key required.\n"
            "  Set it via:  export GROQ_API_KEY='gsk_...'\n"
            "  Or pass it:  --api-key gsk_..."
        )

    client = Groq(api_key=api_key)
    model  = args.model

    # Filter to requested country
    policy_map = POLICY_MAP
    if args.country:
        if args.country not in POLICY_MAP:
            parser.error(f"Unknown country '{args.country}'. "
                         f"Available: {list(POLICY_MAP.keys())}")
        policy_map = {args.country: POLICY_MAP[args.country]}

    results = []

    for country, pdf_names in policy_map.items():
        log.info(f"\n{'─'*60}")
        log.info(f"Processing: {country}")

        if not pdf_names:
            log.warning(f"  No policy PDFs configured for {country} — skipping.")
            log.warning(f"  Add the PDF filename to POLICY_MAP['{country}'] in this script.")
            results.append({
                "country":       country,
                "unconditional": [],
                "conditional":   [],
                "note":          "No policy PDF configured",
            })
            continue

        # Concatenate text from all PDFs for this country
        all_text = []
        for pdf_name in pdf_names:
            pdf_path = POLICY_DIR / pdf_name
            if not pdf_path.exists():
                log.warning(f"  PDF not found: {pdf_path} — skipping this file.")
                continue
            log.info(f"  Reading: {pdf_name}")
            try:
                text = extract_pdf_text(pdf_path)
                all_text.append(text)
                log.info(f"  Extracted {len(text)} chars from {pdf_name}")
            except RuntimeError as e:
                log.error(f"  {e}")

        if not all_text:
            log.warning(f"  No readable text extracted for {country} — skipping LLM call.")
            results.append({
                "country":       country,
                "unconditional": [],
                "conditional":   [],
                "note":          "PDF text extraction failed",
            })
            continue

        combined_text = "\n\n---\n\n".join(all_text)

        try:
            result = query_llm(client, country, combined_text, model)
            log.info(f"  → Unconditional: {result['unconditional']}")
            log.info(f"  → Conditional:   {result['conditional']}")
            results.append(result)
        except Exception as e:
            log.error(f"  LLM query failed for {country}: {e}")
            results.append({
                "country":       country,
                "unconditional": [],
                "conditional":   [],
                "note":          f"LLM error: {e}",
            })

    # Write outputs
    log.info(f"\n{'─'*60}")
    write_json(results)
    write_python_config(results)

    log.info("\nDone. Next steps:")
    log.info("  1. Review extracted_permissions.json for accuracy")
    log.info("  2. permission_sets.py is ready for import in analyzeapk.py")
    log.info("  3. Run the pipeline:  python3 pipeline.py --from permission")


if __name__ == "__main__":
    main()
