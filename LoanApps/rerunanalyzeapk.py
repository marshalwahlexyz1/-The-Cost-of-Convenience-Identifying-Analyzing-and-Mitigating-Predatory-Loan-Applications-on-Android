#code to rerun analysis with newer permission set
#!/usr/bin/env python3
# rerunanalyzeapk.py — country-scoped permission audit with resilient parsing, mismatch stats & failure logging

import os, csv, zipfile, tempfile, logging, traceback, shutil, subprocess, glob
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter
from androguard.core.apk import APK

# ====== CONFIG ======
ROOT_DIR = "/data/olawalea/LoanApps"
ALLOWED_TOP_DIRS = [
    "KenyaApproved",
    "IndonesiaApproved",
    "NigeriaApproved",
    "NigeriaDelisted",
    "PakistanApproved",
    "PakistanDelisted",
    "PhilippinesApproved",
    "PhilippinesDelisted",
]
OUT_CSV = "newpermission_report.csv"
SUMMARY_CSV = "newprocessing_summary.csv"
FAILURES_CSV = "newfailures.csv"
LOG_FILE = "newprocessing_errors.log"
STACK_SNIPPET_LINES = 6
SDK_SEARCH = True  # search common Android SDK locations for aapt/aapt2/apkanalyzer
# ====================

# ---- Permission groups ----
READ_MEDIA = {"android.permission.READ_MEDIA_IMAGES","android.permission.READ_MEDIA_VIDEO","android.permission.READ_MEDIA_AUDIO"}
LEGACY_STORAGE = {"android.permission.READ_EXTERNAL_STORAGE","android.permission.WRITE_EXTERNAL_STORAGE","android.permission.MANAGE_EXTERNAL_STORAGE"}
CONTACTS = {"android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS","android.permission.GET_ACCOUNTS"}
CALL_LOG = {"android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG","android.permission.PROCESS_OUTGOING_CALLS"}
TELEPHONY_MISC = {"android.permission.READ_PHONE_STATE","android.permission.ANSWER_PHONE_CALLS","android.permission.CALL_PHONE","android.permission.READ_PHONE_NUMBERS"}
SMS = {"android.permission.READ_SMS","android.permission.RECEIVE_SMS","android.permission.SEND_SMS"}
LOCATION = {"android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION"}
AUDIO_CAMERA = {"android.permission.CAMERA","android.permission.RECORD_AUDIO"}
MISC = {"android.permission.QUERY_ALL_PACKAGES"}

# ---- Country UNCONDITIONAL bans ----
COUNTRY_UNCONDITIONAL: Dict[str, Set[str]] = {
    "Indonesia": set(),
    "Kenya": set().union(CONTACTS, CALL_LOG),
    "Nigeria": set().union(CONTACTS, CALL_LOG, READ_MEDIA, LEGACY_STORAGE),
    "Pakistan": set().union(CONTACTS, READ_MEDIA, LEGACY_STORAGE, SMS),
    "Philippines": set().union(CONTACTS),
}

# ---- EXACT Google set (only these 8) ----
GOOGLE_PERMS: Set[str] = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

# LoanWatch = union of all country bans ∪ Google (so LoanWatch ≥ Google)
LOANWATCH_PERMS: Set[str] = set().union(*COUNTRY_UNCONDITIONAL.values()) | GOOGLE_PERMS

# Compact per-permission columns = LoanWatch ∪ Google 8
PERMISSION_COLUMNS: List[str] = sorted(LOANWATCH_PERMS | GOOGLE_PERMS)
COUNTRIES = list(COUNTRY_UNCONDITIONAL.keys())

# ---------- logging ----------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logging.getLogger().addHandler(console)

# ---------- helpers ----------
def extract_xapk(xapk_path: str, extract_dir: str) -> Optional[str]:
    with zipfile.ZipFile(xapk_path, "r") as z:
        z.extractall(extract_dir)
    candidates = []
    for r, _, fs in os.walk(extract_dir):
        for f in fs:
            if f.lower().endswith(".apk"):
                candidates.append(os.path.join(r, f))
    if not candidates:
        return None
    for p in candidates:
        if os.path.basename(p).lower() == "base.apk":
            return p
    return max(candidates, key=lambda p: os.path.getsize(p))

def parse_top_dir(name: str) -> Tuple[str, str]:
    n = name.lower()
    for country in COUNTRIES:
        if country.lower() in n:
            cls = "Approved" if "approved" in n else ("Delisted" if "delisted" in n else "Unknown")
            return country, cls
    return "Unknown", "Unknown"

def walk_allowed_files() -> List[Tuple[str, str, str, str]]:
    triples = []
    for top in ALLOWED_TOP_DIRS:
        top_path = os.path.join(ROOT_DIR, top)
        if not os.path.isdir(top_path):
            logging.warning(f"Missing folder (skipped): {top_path}")
            continue
        country, classification = parse_top_dir(top)
        for r, _, files in os.walk(top_path):
            for f in files:
                lf = f.lower()
                if lf.endswith(".apk") or lf.endswith(".xapk"):
                    triples.append((os.path.join(r, f), country, classification, top_path))
    return triples

def evaluate_country(perms: Set[str], app_country: str) -> Tuple[bool, List[str]]:
    banned = COUNTRY_UNCONDITIONAL.get(app_country, set())
    triggers = sorted(perms & banned) if banned else []
    return bool(triggers), triggers

def failure_row(file_path: str, country: str, classification: str, stage: str, err: Exception, hint: str = "") -> Dict[str, str]:
    tb = traceback.format_exc().strip().splitlines()[-STACK_SNIPPET_LINES:]
    return {
        "File": file_path,
        "Country": country,
        "Classification": classification,
        "Stage": stage,
        "ErrorType": type(err).__name__,
        "ErrorMessage": str(err),
        "Hint": hint,
        "TracebackTail": " | ".join(tb),
    }

def safe(val) -> str:
    try:
        return "" if val is None else str(val)
    except Exception:
        return ""

# ---------- tool discovery ----------
def find_build_tool(names: List[str]) -> Optional[str]:
    for env in ("AAPT_PATH", "AAPT2_PATH", "APKANALYZER_PATH"):
        p = os.environ.get(env)
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    if not SDK_SEARCH:
        return None
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"), os.path.expanduser("~/Android/Sdk")]
    candidates = []
    for root in roots:
        if not root:
            continue
        for pattern in ("build-tools/*/aapt*", "build-tools/*/apkanalyzer*"):
            candidates.extend(glob.glob(os.path.join(root, pattern)))
    def ver_key(path: str):
        parts = path.split(os.sep)
        for i, p in enumerate(parts):
            if p == "build-tools" and i+1 < len(parts):
                return parts[i+1]
        return ""
    if candidates:
        candidates.sort(key=ver_key, reverse=True)
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
    return None

def pick_sdk_tool() -> Optional[Tuple[str, List[str], str]]:
    for tool, args, kind in (
        (find_build_tool(["apkanalyzer"]), ["manifest", "permissions"], "APK_ANALYZER"),
        (find_build_tool(["aapt2"]), ["dump", "badging"], "AAPT2"),
        (find_build_tool(["aapt"]), ["dump", "badging"], "AAPT"),
    ):
        if tool:
            return tool, args, kind
    return None

# ---------- parsers ----------
def parse_with_androguard(path: str) -> Dict[str, str]:
    apk = APK(path)
    try:
        version_name = apk.get_androidversion_name()
    except Exception:
        try:
            av = apk.get_androidversion() or {}
            version_name = av.get("Name", "")
        except Exception:
            version_name = ""
    try:
        version_code = apk.get_androidversion_code()
    except Exception:
        try:
            av = apk.get_androidversion() or {}
            version_code = av.get("Code", "")
        except Exception:
            version_code = ""
    return {
        "permissions": set(apk.get_permissions() or []),
        "app_name": safe(apk.get_app_name()),
        "package": safe(apk.get_package()),
        "version_name": safe(version_name),
        "version_code": safe(version_code),
        "min_sdk": safe(apk.get_min_sdk_version()),
        "target_sdk": safe(apk.get_target_sdk_version()),
    }

def parse_with_pyaxmlparser(path: str) -> Dict[str, str]:
    from pyaxmlparser import APK as PAXPK
    papk = PAXPK(path)
    perms = set(papk.get_permissions() or [])
    return {
        "permissions": perms,
        "app_name": safe(getattr(papk, "application", "")),
        "package": safe(getattr(papk, "package", "")),
        "version_name": safe(getattr(papk, "version_name", "")),
        "version_code": safe(getattr(papk, "version_code", "")),
        "min_sdk": safe(getattr(papk, "min_sdk_version", "")),
        "target_sdk": safe(getattr(papk, "target_sdk_version", "")),
    }

def parse_with_apkutils2(path: str) -> Dict[str, str]:
    from apkutils2 import APK as UAPK
    u = UAPK(path)
    m = u.get_manifest() or {}
    perms = set()
    up = m.get("uses-permission") or []
    if isinstance(up, dict):
        up = [up]
    for item in up:
        if not isinstance(item, dict):
            continue
        name = item.get("@android:name") or item.get("name") or item.get("@name")
        if name:
            perms.add(name)
    pkg = ""
    vname = ""
    vcode = ""
    man_root = m.get("manifest") or m
    if isinstance(man_root, dict):
        pkg = man_root.get("@package", "") or man_root.get("package", "")
        vname = man_root.get("@android:versionName", "") or man_root.get("@versionName", "") or man_root.get("versionName", "")
        vcode = man_root.get("@android:versionCode", "") or man_root.get("@versionCode", "") or man_root.get("versionCode", "")
    return {
        "permissions": perms,
        "app_name": "",
        "package": safe(pkg),
        "version_name": safe(vname),
        "version_code": safe(vcode),
        "min_sdk": "",
        "target_sdk": "",
    }

def parse_with_sdk_tool(path: str) -> Optional[Dict[str, str]]:
    picked = pick_sdk_tool()
    if not picked:
        return None
    exe, args, kind = picked
    out = subprocess.check_output([exe, *args, path], stderr=subprocess.STDOUT, text=True, timeout=90)
    perms = set()
    pkg = ""
    vname = ""
    vcode = ""
    for line in out.splitlines():
        line = line.strip()
        if kind == "APK_ANALYZER":
            if line:
                perms.add(line)
        else:
            if line.startswith("package:"):
                if "name='" in line:
                    pkg = line.split("name='",1)[1].split("'",1)[0]
                if "versionName='" in line:
                    vname = line.split("versionName='",1)[1].split("'",1)[0]
                if "versionCode='" in line:
                    vcode = line.split("versionCode='",1)[1].split("'",1)[0]
            elif line.startswith("uses-permission:") and "name='" in line:
                perms.add(line.split("name='",1)[1].split("'",1)[0])
    return {
        "permissions": perms,
        "app_name": "",
        "package": pkg,
        "version_name": vname,
        "version_code": vcode,
        "min_sdk": "",
        "target_sdk": "",
    }

def parse_any(path: str) -> Tuple[Optional[Dict[str, str]], str, Optional[str]]:
    # Androguard
    try:
        info = parse_with_androguard(path)
        return info, "ANDROGUARD", None
    except Exception as e1:
        logging.error(f"[PARSE ANDROGUARD FAIL] {path}: {e1}")
    # apkutils2
    try:
        from apkutils2 import APK as _  # presence check
        info = parse_with_apkutils2(path)
        return info, "APKUTILS2", None
    except Exception as e2:
        logging.error(f"[PARSE APKUTILS2 FAIL] {path}: {e2}")
    # pyaxmlparser
    try:
        from pyaxmlparser import APK as _  # presence check
        info = parse_with_pyaxmlparser(path)
        return info, "PYAXMLPARSER", None
    except Exception as e3:
        logging.error(f"[PARSE PYAXMLPARSER FAIL] {path}: {e3}")
    # SDK tools
    try:
        info = parse_with_sdk_tool(path)
        if info:
            return info, "SDK_TOOL", None
        hint = "Install Android SDK build-tools (aapt/aapt2/apkanalyzer) or set AAPT_PATH/AAPT2_PATH/APKANALYZER_PATH."
        return None, "NONE", hint
    except Exception as e4:
        logging.error(f"[PARSE SDK TOOL FAIL] {path}: {e4}")
        hint = "Install Android SDK build-tools (aapt/aapt2/apkanalyzer) or set AAPT_PATH/AAPT2_PATH/APKANALYZER_PATH."
        return None, "NONE", hint

# ---------- pipeline ----------
def analyze_file(path: str, app_country: str, classification: str) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    try:
        original = path
        if path.lower().endswith(".xapk"):
            try:
                with tempfile.TemporaryDirectory(prefix="xapk_") as tmp:
                    ap = extract_xapk(path, tmp)
                    if not ap:
                        raise RuntimeError("No .apk found inside .xapk")
                    info, stage, hint = parse_any(ap)
                    if not info:
                        raise RuntimeError(hint or "All parsers failed")
                    rec = build_record(info, original, app_country, classification)
                    return rec, None
            except Exception as e:
                return None, failure_row(original, app_country, classification, "XAPK_PARSE", e, hint if 'hint' in locals() else "")
        else:
            info, stage, hint = parse_any(path)
            if not info:
                raise RuntimeError(hint or "All parsers failed")
            rec = build_record(info, original, app_country, classification)
            return rec, None
    except Exception as e:
        return None, failure_row(path, app_country, classification, "ANALYZE", e)

def build_record(info: Dict[str, str], original_path: str, app_country: str, classification: str) -> Dict[str, str]:
    perms = set(info.get("permissions") or [])
    v_country, t_country = evaluate_country(perms, app_country)
    trig_google = sorted(perms & GOOGLE_PERMS)
    trig_loan = sorted(perms & LOANWATCH_PERMS)

    rec: Dict[str, str] = {
        "File": original_path,
        "App Name": info.get("app_name",""),
        "Package Name": info.get("package",""),
        "Version Name": info.get("version_name",""),
        "Version Code": str(info.get("version_code","")),
        "Min SDK": str(info.get("min_sdk","")),
        "Target SDK": str(info.get("target_sdk","")),
        "Country/Classification": f"{app_country}/{classification}",
        "Declared Permissions": ";".join(sorted(perms)),
    }

    for p in PERMISSION_COLUMNS:
        rec[p] = "Yes" if p in perms else "No"

    for c in COUNTRIES:
        if c == app_country:
            rec[f"Violate_{c}"] = "TRUE" if v_country else "FALSE"
            rec[f"{c}_Triggers"] = ";".join(t_country) if t_country else ""
        else:
            rec[f"Violate_{c}"] = "N/A"
            rec[f"{c}_Triggers"] = ""

    rec["Violate_Google"] = "TRUE" if trig_google else "FALSE"
    rec["Google_Triggers"] = ";".join(trig_google)
    rec["Violate_LoanWatch"] = "TRUE" if trig_loan else "FALSE"
    rec["LoanWatch_Triggers"] = ";".join(trig_loan)
    return rec

def fmt_counts(counter: Counter) -> str:
    if not counter:
        return ""
    # sort by desc count, then name
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return " | ".join([f"{k}={v}" for k, v in items])

def main():
    records: List[Dict[str, str]] = []
    failures: List[Dict[str, str]] = []
    folder_stats: Dict[str, Dict[str, object]] = {}

    file_triples = []
    for top in ALLOWED_TOP_DIRS:
        top_path = os.path.join(ROOT_DIR, top)
        if not os.path.isdir(top_path):
            continue
        country, classification = parse_top_dir(top)
        for r, _, files in os.walk(top_path):
            for f in files:
                lf = f.lower()
                if lf.endswith(".apk") or lf.endswith(".xapk"):
                    file_triples.append((os.path.join(r, f), country, classification, top_path))

    for path, country, classification, top_path in file_triples:
        folder_stats.setdefault(top_path, {
            "total": 0, "processed": 0, "failed": 0, "failed_files": [],
            "viol_country": 0, "viol_google": 0, "viol_loan": 0,
            "country_only_count": 0, "country_only_perm_counts": Counter(),
            "google_only_count": 0,  "google_only_perm_counts": Counter(),
        })
        folder_stats[top_path]["total"] += 1

        rec, fail = analyze_file(path, country, classification)
        if rec:
            records.append(rec)
            folder_stats[top_path]["processed"] += 1

            v_country = rec.get(f"Violate_{country}") == "TRUE"
            v_google  = rec.get("Violate_Google") == "TRUE"
            v_loan    = rec.get("Violate_LoanWatch") == "TRUE"

            if v_country:
                folder_stats[top_path]["viol_country"] += 1
            if v_google:
                folder_stats[top_path]["viol_google"] += 1
            if v_loan:
                folder_stats[top_path]["viol_loan"] += 1

            # Mismatch tallies
            if v_country and not v_google:
                folder_stats[top_path]["country_only_count"] += 1
                trig = rec.get(f"{country}_Triggers","")
                if trig:
                    for p in [t for t in trig.split(";") if t]:
                        folder_stats[top_path]["country_only_perm_counts"][p] += 1
            elif v_google and not v_country:
                folder_stats[top_path]["google_only_count"] += 1
                gtrig = rec.get("Google_Triggers","")
                if gtrig:
                    for p in [t for t in gtrig.split(";") if t]:
                        folder_stats[top_path]["google_only_perm_counts"][p] += 1
        else:
            folder_stats[top_path]["failed"] += 1
            folder_stats[top_path]["failed_files"].append(os.path.basename(path))
            if fail:
                failures.append(fail)

    # per-app CSV
    fixed = [
        "File","App Name","Package Name","Version Name","Version Code",
        "Min SDK","Target SDK","Country/Classification","Declared Permissions"
    ]
    country_cols = []
    for c in COUNTRIES:
        country_cols += [f"Violate_{c}", f"{c}_Triggers"]
    tail = ["Violate_Google","Google_Triggers","Violate_LoanWatch","LoanWatch_Triggers"]
    fieldnames = fixed + PERMISSION_COLUMNS + country_cols + tail

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            w.writerow(rec)

    # per-folder summary CSV (with mismatch details)
    summary_headers = [
        "Folder","Total Files","Processed","Failed",
        "Country Violations","Google Violations","LoanWatch Violations",
        "CountryOnly Violators","CountryOnly PermCounts",
        "GoogleOnly Violators","GoogleOnly PermCounts",
    ]
    totals = {
        "total":0,"processed":0,"failed":0,
        "viol_country":0,"viol_google":0,"viol_loan":0,
        "country_only_count":0,"google_only_count":0,
    }

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=summary_headers)
        w.writeheader()
        for top in ALLOWED_TOP_DIRS:
            top_path = os.path.join(ROOT_DIR, top)
            stats = folder_stats.get(top_path, {
                "total":0,"processed":0,"failed":0,
                "viol_country":0,"viol_google":0,"viol_loan":0,
                "country_only_count":0,"country_only_perm_counts":Counter(),
                "google_only_count":0,"google_only_perm_counts":Counter(),
            })
            w.writerow({
                "Folder": top_path,
                "Total Files": stats["total"],
                "Processed": stats["processed"],
                "Failed": stats["failed"],
                "Country Violations": stats["viol_country"],
                "Google Violations": stats["viol_google"],
                "LoanWatch Violations": stats["viol_loan"],
                "CountryOnly Violators": stats["country_only_count"],
                "CountryOnly PermCounts": fmt_counts(stats["country_only_perm_counts"]),
                "GoogleOnly Violators": stats["google_only_count"],
                "GoogleOnly PermCounts": fmt_counts(stats["google_only_perm_counts"]),
            })
            totals["total"] += stats["total"]
            totals["processed"] += stats["processed"]
            totals["failed"] += stats["failed"]
            totals["viol_country"] += stats["viol_country"]
            totals["viol_google"] += stats["viol_google"]
            totals["viol_loan"] += stats["viol_loan"]
            totals["country_only_count"] += stats["country_only_count"]
            totals["google_only_count"] += stats["google_only_count"]

        w.writerow({
            "Folder": "ALL",
            "Total Files": totals["total"],
            "Processed": totals["processed"],
            "Failed": totals["failed"],
            "Country Violations": totals["viol_country"],
            "Google Violations": totals["viol_google"],
            "LoanWatch Violations": totals["viol_loan"],
            "CountryOnly Violators": totals["country_only_count"],
            "CountryOnly PermCounts": "",  # aggregated perm breakdown across all folders would be noisy; can add if needed
            "GoogleOnly Violators": totals["google_only_count"],
            "GoogleOnly PermCounts": "",
        })

    # failures CSV
    if failures:
        with open(FAILURES_CSV, "w", newline="", encoding="utf-8") as f:
            cols = ["File","Country","Classification","Stage","ErrorType","ErrorMessage","Hint","TracebackTail"]
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for row in failures:
                w.writerow(row)

    # console summary
    print("Processing Summary by Folder:")
    for top in ALLOWED_TOP_DIRS:
        tp = os.path.join(ROOT_DIR, top)
        s = folder_stats.get(tp, {
            "total":0,"processed":0,"failed":0,
            "viol_country":0,"viol_google":0,"viol_loan":0,
            "country_only_count":0,"country_only_perm_counts":Counter(),
            "google_only_count":0,"google_only_perm_counts":Counter(),
            "failed_files":[]
        })
        print(f"- {tp}")
        print(f"  Total:     {s['total']}")
        print(f"  Processed: {s['processed']}")
        print(f"  Failed:    {s['failed']}")
        print(f"  Violations -> Country: {s['viol_country']}  Google: {s['viol_google']}  LoanWatch: {s['viol_loan']}")
        print(f"  CountryOnly: {s['country_only_count']}  ({fmt_counts(s['country_only_perm_counts'])})")
        print(f"  GoogleOnly : {s['google_only_count']}   ({fmt_counts(s['google_only_perm_counts'])})")
        if s["failed_files"]:
            print(f"  Failed Files: {', '.join(s['failed_files'])}")
    print(f"\nWrote: {OUT_CSV}")
    print(f"Wrote: {SUMMARY_CSV}")
    if failures:
        print(f"Wrote: {FAILURES_CSV}")
        print(f"Errors log: {LOG_FILE}")

if __name__ == "__main__":
    main()
