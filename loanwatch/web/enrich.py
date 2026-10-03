"""
Report enrichments for the LoanWatch web app:

  evidence_fingerprint  hashes, signing certificate, versions: proves which file was analysed
  code_hiding           packers, native libraries, dynamic code loading, reflection
  registry_lookup       paper dataset + national lender lists (data/registries.json)
  play_store            Google Play listing + Data safety section (live apps only)
  privacy_policy_check  AI reads the app's own privacy policy

Every function returns plain JSON-able dicts and never raises: a failure is
recorded in the result so the report can say what could not be checked.
"""
import hashlib
import html
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
LOANWATCH_DIR = os.path.dirname(HERE)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# ── 1. Evidence fingerprint ──────────────────────────────────────────────────

def _hashes(path):
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for x in h.values():
                x.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


def _git_commit():
    try:
        out = subprocess.run(["git", "-C", LOANWATCH_DIR, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return ""


def _certificates(apk):
    certs = []
    try:
        for c in apk.get_certificates():
            der = c.dump()
            certs.append({
                "sha256": hashlib.sha256(der).hexdigest(),
                "sha1": hashlib.sha1(der).hexdigest(),
                "subject": c.subject.human_friendly,
                "issuer": c.issuer.human_friendly,
                "valid_from": str(c["tbs_certificate"]["validity"]["not_before"].native),
                "valid_to": str(c["tbs_certificate"]["validity"]["not_after"].native),
                "self_signed": c.self_signed != "no",
            })
    except Exception as e:
        certs.append({"error": f"{type(e).__name__}: {e}"})
    schemes = []
    for name, fn in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"), ("v3", "is_signed_v3")):
        try:
            if getattr(apk, fn)():
                schemes.append(name)
        except Exception:
            pass
    return certs, schemes


def evidence_fingerprint(apk_path, apk, policy_path="", tool_versions=None):
    out = {"scanned_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        out["apk_file"] = os.path.basename(apk_path)
        out["apk_bytes"] = os.path.getsize(apk_path)
        out["apk_hashes"] = _hashes(apk_path)
    except Exception as e:
        out["apk_hashes"] = {"error": str(e)}
    try:
        out["version_name"] = apk.get_androidversion_name()
        out["version_code"] = apk.get_androidversion_code()
        out["min_sdk"] = apk.get_min_sdk_version()
        out["target_sdk"] = apk.get_target_sdk_version()
    except Exception:
        pass
    out["certificates"], out["signature_schemes"] = _certificates(apk)
    if policy_path and os.path.exists(policy_path):
        out["policy_file"] = os.path.basename(policy_path)
        out["policy_sha256"] = _hashes(policy_path)["sha256"]
    versions = {"loanwatch_commit": _git_commit(), "python": platform.python_version(),
                "os": f"{platform.system()} {platform.release()}"}
    try:
        import androguard
        versions["androguard"] = getattr(androguard, "__version__", "")
    except Exception:
        pass
    versions.update(tool_versions or {})
    out["tool_versions"] = versions
    return out


# ── 3. Code hiding: packers, native code, dynamic loading ────────────────────

# library file name / class name → packer.  Sources: public APKiD rules.
_PACKER_LIBS = [
    (r"libjiagu", "Qihoo 360 Jiagu"), (r"libprotectClass|libjiagu_art", "Qihoo 360 Jiagu"),
    (r"libsecexe|libsecmain|libSecShell|libDexHelper", "Bangcle / SecNeo"),
    (r"libshell[a-z]?-|libshellx|libtxAppEntry|libBugly-?legu|liblegudb", "Tencent Legu"),
    (r"libexec\.so|libexecmain|libijiami", "ijiami"),
    (r"libbaiduprotect", "Baidu protection"),
    (r"libmobisec|libsgmain|libsgsecuritybody|libaliutils", "Alibaba security"),
    (r"libnqshield", "NQ Shield"), (r"libnesec", "NetEase Yidun"),
    (r"libkwscmm|libkwslinker", "Kiwisec"), (r"libapktoolplus|libAPKProtect", "APKProtect"),
    (r"libdexprotector|libdpboot", "DexProtector"), (r"libjgdtc|libjgbibc", "Jiagu (variant)"),
    (r"libtup\.so|libuusafe", "UU Safe"), (r"libvdog|libedog", "Virbox / eDog"),
    (r"libapp_protect|libsecenh", "Generic protector"),
]
_PACKER_CLASSES = [
    (r"com/stub/StubApp|com/qihoo/util/", "Qihoo 360 Jiagu"),
    (r"com/secneo/apkwrapper|com/secshell/", "Bangcle / SecNeo"),
    (r"com/tencent/StubShell|com/tencent/bugly/legu", "Tencent Legu"),
    (r"com/shell/SuperApplication|s/h/e/l/l/", "ijiami"),
    (r"com/baidu/protect", "Baidu protection"),
    (r"com/ali/mobisecenhance", "Alibaba security"),
    (r"com/nqshield", "NQ Shield"), (r"com/netease/nis/wrapper", "NetEase Yidun"),
    (r"com/kiwisec", "Kiwisec"), (r"com/licel/dexprotector|dexprotector", "DexProtector"),
    (r"com/zhuowang/|com/payegis/", "Payegis"),
]
_DATA_STRINGS = {
    b"content://com.android.contacts": "Contacts", b"content://contacts": "Contacts",
    b"content://call_log": "Call log", b"content://sms": "SMS", b"content://mms": "SMS",
    b"content://media": "Photos, media & storage",
    b"getLastKnownLocation": "Location", b"getDeviceId": "Phone", b"getLine1Number": "Phone",
}
_DYNAMIC = {
    "Ldalvik/system/DexClassLoader;": "DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader;": "InMemoryDexClassLoader",
    "Ldalvik/system/PathClassLoader;": "PathClassLoader",
    "Ldalvik/system/BaseDexClassLoader;": "BaseDexClassLoader",
}
_SAFE_PREFIX = ("Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lcom/google/",
                "Ldalvik/", "Lorg/apache/", "Lokhttp3/", "Lcom/facebook/", "Lio/flutter/")


def code_hiding(apk, analysis, apk_path):
    out = {"packers": [], "native_libs": [], "native_data_strings": [], "dynamic_loading": [],
           "reflection_calls": 0, "dex_files": 0, "embedded_dex_or_jar": [], "obfuscation": None,
           "application_class": ""}
    found = {}
    try:
        files = apk.get_files()
    except Exception:
        files = []
    out["dex_files"] = sum(1 for f in files if re.match(r"classes\d*\.dex$", f))
    libs = [f for f in files if f.startswith("lib/") and f.endswith(".so")]
    abis = sorted({f.split("/")[1] for f in libs if f.count("/") >= 2})
    names = sorted({os.path.basename(f) for f in libs})
    out["native_libs"] = names
    out["native_abis"] = abis
    for n in names:
        for rx, packer in _PACKER_LIBS:
            if re.search(rx, n, re.I):
                found.setdefault(packer, []).append(f"native library {n}")
    out["embedded_dex_or_jar"] = [f for f in files if re.search(r"\.(dex|jar|odex)$", f, re.I)
                                  and not re.match(r"classes\d*\.dex$", f)][:20]
    try:
        out["application_class"] = apk.get_attribute_value("application", "name") or ""
    except Exception:
        pass
    # class names
    class_names = []
    try:
        class_names = [c.name for c in analysis.get_classes() if not c.is_external()]
    except Exception:
        pass
    joined = "\n".join(class_names) + "\n" + out["application_class"].replace(".", "/")
    for rx, packer in _PACKER_CLASSES:
        m = re.search(rx, joined)
        if m:
            found.setdefault(packer, []).append(f"class {m.group(0)}")
    out["packers"] = [{"name": k, "evidence": v[:4]} for k, v in found.items()]

    # obfuscation: share of app classes whose simple name is 1–2 characters
    app_classes = [c for c in class_names if not c.startswith(_SAFE_PREFIX)]
    if app_classes:
        short = sum(1 for c in app_classes if len(c.strip("L;").split("/")[-1].split("$")[0]) <= 2)
        out["obfuscation"] = {"app_classes": len(app_classes),
                              "short_name_share": round(short / len(app_classes), 2)}

    # dynamic code loading + reflection, called from app code only
    try:
        for cls, label in _DYNAMIC.items():
            n = 0
            for m in analysis.find_methods(classname=re.escape(cls), methodname="<init>"):
                n += sum(1 for _, caller, _ in m.get_xref_from()
                         if not caller.class_name.startswith(_SAFE_PREFIX))
            if n:
                out["dynamic_loading"].append({"api": label, "call_sites": n})
        refl = 0
        for m in analysis.find_methods(classname=r"Ljava/lang/reflect/Method;", methodname="invoke"):
            refl += sum(1 for _, caller, _ in m.get_xref_from()
                        if not caller.class_name.startswith(_SAFE_PREFIX))
        out["reflection_calls"] = refl
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"

    # native libraries that contain data-access strings (contacts, SMS …)
    try:
        with zipfile.ZipFile(apk_path) as z:
            seen = set()
            for f in libs:
                info = z.getinfo(f)
                if info.file_size > 40 * 2**20:
                    continue
                blob = z.read(f)
                for needle, cat in _DATA_STRINGS.items():
                    if needle in blob and (os.path.basename(f), cat) not in seen:
                        seen.add((os.path.basename(f), cat))
                        out["native_data_strings"].append(
                            {"library": os.path.basename(f), "string": needle.decode(), "category": cat})
    except Exception:
        pass

    reasons = []
    if out["packers"]:
        reasons.append("packed with " + ", ".join(p["name"] for p in out["packers"]))
    if out["dynamic_loading"]:
        reasons.append("loads extra code at runtime")
    if out["native_data_strings"]:
        reasons.append("native libraries reference personal-data APIs")
    if out["embedded_dex_or_jar"]:
        reasons.append("ships extra code files inside the APK")
    out["hides_code"] = bool(reasons)
    out["reasons"] = reasons
    return out


# ── 2. Lender registries ─────────────────────────────────────────────────────

_REG = None
_LEGAL = r"\b(limited|ltd|pvt|private|plc|inc|pt|tbk|company|co|llc|corp|corporation|the)\b"


def _norm(name):
    s = re.sub(r"[^a-z0-9 ]+", " ", (name or "").lower())
    s = re.sub(_LEGAL, " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _registry():
    global _REG
    if _REG is None:
        try:
            with open(os.path.join(LOANWATCH_DIR, "data", "registries.json"), encoding="utf-8") as f:
                _REG = json.load(f)
        except Exception:
            _REG = {"sources": [], "packages": {}, "names": []}
    return _REG


def registry_lookup(package, app_name="", developer=""):
    reg = _registry()
    exact = [dict(e, match="package") for e in reg["packages"].get(package, [])]
    candidates = {k for k in (_norm(app_name), _norm(developer)) if len(k) >= 4}
    names = []
    for e in reg["names"]:
        k = e["key"]
        hit = k in candidates or any(
            len(k.split()) >= 2 and re.search(rf"\b{re.escape(k)}\b", c) for c in candidates)
        if hit:
            names.append(dict(e, match="name"))
    # one row per source
    seen, uniq = set(), []
    for e in exact + names:
        key = (e["source"], e.get("country"), e.get("status") or e.get("kind"))
        if key not in seen:
            seen.add(key)
            uniq.append(e)

    def status_of(e):
        s = (e.get("status") or e.get("kind") or "").lower()
        if s in ("delisted", "reported", "third_party_reported"):
            return "flagged"
        if s in ("approved", "licensed", "third_party_licensed"):
            return "listed"
        return "other"

    verdict = "unknown"
    if any(status_of(e) == "flagged" for e in uniq):
        verdict = "flagged"
    elif any(status_of(e) == "listed" for e in uniq):
        verdict = "listed"
    return {
        "verdict": verdict,          # flagged | listed | unknown
        "matches": uniq,
        "sources_checked": [s.get("source") for s in reg["sources"]],
        "note": ("Package matches are exact. Name matches compare the app or developer name "
                 "with the list and must be verified by hand."),
    }


# ── 5. Google Play listing + Data safety ─────────────────────────────────────

_COUNTRY_CODE = {"nigeria": "ng", "kenya": "ke", "pakistan": "pk", "philippines": "ph",
                 "indonesia": "id", "india": "in", "ghana": "gh", "uganda": "ug",
                 "tanzania": "tz", "south africa": "za", "mexico": "mx", "colombia": "co"}

# Data safety section → our display categories
DS_CATEGORIES = {
    "Location": ["Location"],
    "Personal info": ["Phone"],
    "Financial info": [],
    "Messages": ["SMS"],
    "Photos and videos": ["Photos, media & storage", "Camera"],
    "Audio": ["Microphone"],
    "Files and docs": ["Photos, media & storage"],
    "Calendar": ["Calendar"],
    "Contacts": ["Contacts"],
    "App activity": ["Installed apps"],
    "Web browsing": [],
    "App info and performance": [],
    "Device or other IDs": ["Phone"],
    "Health and fitness": [],
}


def _country_codes(countries):
    """'Nigeria' / 'Nigerian' / 'NG' → 'ng'; always ends with 'us' as a fallback."""
    codes = []
    for c in countries:
        c = (c or "").strip().lower()
        if not c:
            continue
        cc = c if len(c) == 2 else next(
            (code for name, code in _COUNTRY_CODE.items() if c.startswith(name[:5])), "")
        if c.startswith(("filipin", "philippin")):
            cc = "ph"
        if cc and cc not in codes:
            codes.append(cc)
    return codes + ([] if "us" in codes else ["us"])


def _fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def _html_to_lines(page):
    page = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", page)
    page = re.sub(r"(?i)<br\s*/?>|</(div|p|h\d|li|section|span|header)>", "\n", page)
    text = html.unescape(re.sub(r"<[^>]+>", " ", page))
    return [re.sub(r"\s+", " ", l).strip() for l in text.splitlines() if l.strip()]


def parse_data_safety(page):
    """Read the categories listed under 'Data shared' and 'Data collected'."""
    lines = _html_to_lines(page)
    out = {"shared": [], "collected": [], "no_data_shared": False, "no_data_collected": False,
           "parsed": False}
    joined = " \n".join(lines)
    out["no_data_shared"] = bool(re.search(r"No data shared with third parties", joined, re.I))
    out["no_data_collected"] = bool(re.search(r"No data collected", joined, re.I))
    section = None
    for line in lines:
        low = line.lower()
        if low.startswith("data shared"):
            section = "shared"
            continue
        if low.startswith("data collected"):
            section = "collected"
            continue
        if low.startswith(("security practices", "ratings and reviews", "see details", "app support")):
            section = None
            continue
        if section and line in DS_CATEGORIES and line not in out[section]:
            out[section].append(line)
    out["parsed"] = bool(out["shared"] or out["collected"] or out["no_data_shared"]
                         or out["no_data_collected"])
    return out


def play_store(package, countries=()):
    """Listing details and Data safety for a live app; status 'not_found' when removed."""
    out = {"package": package, "status": "error", "checked_at_utc":
           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        from google_play_scraper import app as gp_app
        from google_play_scraper.exceptions import NotFoundError
    except Exception:
        out["error"] = "google-play-scraper is not installed (pip install google-play-scraper)"
        return out
    info, used = None, ""
    for cc in _country_codes(countries):
        try:
            info = gp_app(package, lang="en", country=cc)
            used = cc
            break
        except NotFoundError:
            continue
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            return out
    if info is None:
        out["status"] = "not_found"
        out["note"] = "Not on Google Play (removed, region-locked, or never listed)."
        return out
    keep = ("title", "developer", "developerId", "developerEmail", "developerWebsite",
            "developerAddress", "installs", "realInstalls", "score", "ratings", "reviews",
            "released", "updated", "version", "privacyPolicy", "genre", "contentRating",
            "url", "icon", "summary", "containsAds", "offersIAP")
    out.update({k: info.get(k) for k in keep})
    if isinstance(out.get("updated"), (int, float)):
        out["updated"] = time.strftime("%Y-%m-%d", time.gmtime(out["updated"]))
    out["status"] = "live"
    out["store_country"] = used
    try:
        page = _fetch(f"https://play.google.com/store/apps/datasafety?id={package}&hl=en&gl={used}")
        out["data_safety"] = parse_data_safety(page)
    except Exception as e:
        out["data_safety"] = {"parsed": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}
    return out


def compare_with_store(store, exposure):
    """Rows where the app asks for / reads / sends data the store page doesn't declare."""
    ds = (store or {}).get("data_safety") or {}
    if not ds.get("parsed"):
        return []
    declared = set()
    for cat in ds.get("collected", []) + ds.get("shared", []):
        declared.update(DS_CATEGORIES.get(cat, []))
    rows = []
    for e in exposure:
        if not (e["asks"] or e["reads"] or e["sends"]):
            continue
        ds_names = [k for k, v in DS_CATEGORIES.items() if e["category"] in v]
        if not ds_names:
            continue        # e.g. call log: no matching Data safety category
        rows.append({
            "category": e["category"],
            "data_safety_category": " / ".join(ds_names),
            "declared": e["category"] in declared,
            "evidence": ("sends" if e["sends"] else "reads" if e["reads"] else "asks"),
        })
    return rows


# ── 5b. Privacy policy, read by the AI ───────────────────────────────────────

def privacy_policy_check(url, groq_key, model, categories):
    out = {"url": url, "status": "skipped"}
    if not url:
        out["note"] = "No privacy policy link on the store page."
        return out
    if not groq_key:
        out["note"] = "AI is off (no Groq key)."
        return out
    try:
        text = " ".join(_html_to_lines(_fetch(url)))[:14000]
    except Exception as e:
        out.update(status="error", note=f"Could not download the policy ({type(e).__name__}).")
        return out
    if len(text) < 200:
        out.update(status="error", note="The policy page had almost no text (it may need JavaScript).")
        return out
    try:
        from groq import Groq
        cats = ", ".join(categories) or "Contacts, Call log, SMS, Photos, Location, Phone"
        prompt = f"""You are checking a loan app's privacy policy for a compliance report.

Privacy policy text:
---
{text}
---

For each of these data types: {cats}
say whether the policy states the app collects or accesses it, and copy the shortest
supporting sentence. Use "not mentioned" when the policy says nothing about it.

Respond with ONLY valid JSON:
{{"items": [{{"category": "Contacts", "stated": "yes" | "no" | "not mentioned", "quote": "..."}}],
  "summary": "one sentence"}}"""
        resp = Groq(api_key=groq_key).chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=3000)
        raw = re.sub(r"<think>.*?</think>", "", resp.choices[0].message.content or "", flags=re.S)
        m = re.search(r"\{.*\}", raw, re.S)
        data = json.loads(m.group(0) if m else raw)
        out.update(status="done", items=data.get("items", []), summary=data.get("summary", ""))
    except Exception as e:
        out.update(status="error", note=f"AI step failed ({type(e).__name__}).")
    return out
