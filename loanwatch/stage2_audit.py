"""
Stage 2: Manifest Audit → VIOLATING check

Extracts declared permissions from the APK manifest and checks
which of the prohibited permissions (from Stage 1) are present.
"""
import json
import warnings
warnings.filterwarnings("ignore")

from androguard.misc import AnalyzeAPK


def run(apk_path: str, prohibited_permissions: list,
        verbose: bool = True) -> dict:
    """
    Returns:
        {
          "violating": True/False,
          "matched_permissions": ["READ_CONTACTS", ...],
          "all_declared_permissions": [...],
          "package": "...",
          "app_name": "..."
        }
    """
    if verbose:
        print("[Stage 2] Loading APK manifest...")

    apk, _, _ = AnalyzeAPK(apk_path)

    declared = sorted(apk.get_permissions())
    # Normalize: strip android.permission. prefix for matching
    declared_short = [p.replace("android.permission.", "").upper()
                      for p in declared]

    prohibited_upper = [p.upper() for p in prohibited_permissions]

    matched = []
    for i, short in enumerate(declared_short):
        if short in prohibited_upper:
            matched.append(declared[i])  # keep full name in output

    violating = len(matched) > 0

    result = {
        "package":                  apk.get_package(),
        "app_name":                 apk.get_app_name(),
        "violating":                violating,
        "matched_permissions":      matched,
        "all_declared_permissions": declared,
    }

    if verbose:
        status = "VIOLATING" if violating else "COMPLIANT"
        print(f"[Stage 2] App: {result['app_name']}  ({result['package']})")
        print(f"[Stage 2] Status: {status}")
        if matched:
            print(f"[Stage 2] Prohibited permissions found:")
            for p in matched:
                print(f"   • {p}")

    return result
