"""
Stage 2: Manifest Audit → VIOLATING check

Extracts declared permissions from the APK manifest and checks
which of the prohibited permissions (from Stage 1) are present.
"""
import json
import warnings
warnings.filterwarnings("ignore")

from androguard.misc import AnalyzeAPK


def declared_permissions(apk) -> list:
    """All permissions the manifest requests: <uses-permission> plus the
    runtime-only <uses-permission-sdk-23> / <uses-permission-sdk-m> forms,
    which Androguard's get_permissions() does not include."""
    perms = set(apk.get_permissions())
    for tag in ("uses-permission-sdk-23", "uses-permission-sdk-m"):
        try:
            perms.update(p for p in apk.get_all_attribute_value(tag, "name") if p)
        except Exception:
            pass
    return sorted(perms)


def run(apk_path: str, prohibited_permissions: list,
        verbose: bool = True, apk=None) -> dict:
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

    if apk is None:
        apk, _, _ = AnalyzeAPK(apk_path)

    declared = declared_permissions(apk)
    # Normalize: strip android.permission. prefix for matching
    declared_short = [p.replace("android.permission.", "").upper()
                      for p in declared]

    prohibited_upper = [p.replace("android.permission.", "").upper()
                        for p in prohibited_permissions]

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
