"""
Deterministic helpers for the LoanWatch web app.

These give the web app answers that do not depend on the LLM, so it still
works without a Groq key (or when the LLM returns something unusable):

  * PERMISSION_CATALOG  – sensitive permissions a user can tick by hand
  * baseline_api_targets – permission → bytecode identifiers for Stage 4
  * clean_api_targets    – merges LLM output with the baseline and drops
                           identifiers so generic they match every app
  * frida_template       – a Frida script built directly from the findings
  * detect_trackers      – Exodus Privacy tracker signatures vs. class names
"""
import json
import os
import re

# permission → (data type, human label, bytecode identifiers)
PERMISSION_CATALOG = {
    "READ_CONTACTS": ("contacts", "Contacts / phone book", [
        "ContactsContract", "content://com.android.contacts"]),
    "WRITE_CONTACTS": ("contacts", "Modify contacts", [
        "ContactsContract", "content://com.android.contacts"]),
    "GET_ACCOUNTS": ("accounts", "Accounts on the device", [
        "Landroid/accounts/AccountManager;->getAccounts"]),
    "READ_CALL_LOG": ("call_logs", "Call history", [
        "Landroid/provider/CallLog", "content://call_log"]),
    "WRITE_CALL_LOG": ("call_logs", "Modify call history", [
        "Landroid/provider/CallLog", "content://call_log"]),
    "PROCESS_OUTGOING_CALLS": ("call_logs", "Outgoing calls", [
        "NEW_OUTGOING_CALL"]),
    "READ_SMS": ("sms", "Text messages (SMS)", [
        "Landroid/provider/Telephony$Sms", "content://sms", "content://mms-sms"]),
    "RECEIVE_SMS": ("sms", "Incoming SMS", [
        "SMS_RECEIVED", "Landroid/telephony/SmsMessage;->createFromPdu"]),
    "SEND_SMS": ("sms", "Send SMS", [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/SmsManager;->sendMultipartTextMessage"]),
    "READ_EXTERNAL_STORAGE": ("photos", "Photos, files & storage", [
        "Landroid/provider/MediaStore$Images", "Landroid/provider/MediaStore$Video",
        "content://media", "DIRECTORY_DCIM", "DIRECTORY_PICTURES"]),
    "WRITE_EXTERNAL_STORAGE": ("photos", "Write to storage", [
        "Landroid/os/Environment;->getExternalStorageDirectory"]),
    "MANAGE_EXTERNAL_STORAGE": ("files", "All files on the device", [
        "Landroid/os/Environment;->getExternalStorageDirectory",
        "MANAGE_ALL_FILES_ACCESS_PERMISSION"]),
    "READ_MEDIA_IMAGES": ("photos", "Photos (Android 13+)", [
        "Landroid/provider/MediaStore$Images", "content://media"]),
    "READ_MEDIA_VIDEO": ("videos", "Videos (Android 13+)", [
        "Landroid/provider/MediaStore$Video", "content://media"]),
    "READ_MEDIA_AUDIO": ("audio_files", "Audio files (Android 13+)", [
        "Landroid/provider/MediaStore$Audio"]),
    "CAMERA": ("camera", "Camera", [
        "Landroid/hardware/Camera;->open",
        "Landroid/hardware/camera2/CameraManager;->openCamera"]),
    "RECORD_AUDIO": ("microphone", "Microphone", [
        "Landroid/media/MediaRecorder;->setAudioSource",
        "Landroid/media/AudioRecord;-><init>"]),
    "ACCESS_FINE_LOCATION": ("location", "Precise location (GPS)", [
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/location/LocationManager;->requestLocationUpdates",
        "FusedLocationProviderClient;->getLastLocation"]),
    "ACCESS_COARSE_LOCATION": ("location", "Approximate location", [
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/location/LocationManager;->requestLocationUpdates",
        "FusedLocationProviderClient;->getLastLocation"]),
    "ACCESS_BACKGROUND_LOCATION": ("location", "Location in background", [
        "Landroid/location/LocationManager;->requestLocationUpdates"]),
    "READ_PHONE_STATE": ("device_ids", "Phone number & device IDs", [
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getImei",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/telephony/TelephonyManager;->getLine1Number",
        "Landroid/telephony/TelephonyManager;->getSimSerialNumber"]),
    "READ_PHONE_NUMBERS": ("device_ids", "Phone number", [
        "Landroid/telephony/TelephonyManager;->getLine1Number"]),
    "READ_CALENDAR": ("calendar", "Calendar", [
        "CalendarContract", "content://com.android.calendar"]),
    "QUERY_ALL_PACKAGES": ("installed_apps", "List of installed apps", [
        "Landroid/content/pm/PackageManager;->getInstalledPackages",
        "Landroid/content/pm/PackageManager;->getInstalledApplications"]),
    "BODY_SENSORS": ("health", "Body sensors", [
        "Landroid/hardware/SensorManager;->getDefaultSensor"]),
}

# Identifiers the LLM sometimes returns that appear in almost every app;
# matching on them would flag unrelated code.
_GENERIC = {
    "query", "getcontentresolver", "contentresolver", "cursor", "uri",
    "getstring", "open", "start", "insert", "get", "read", "getcount",
    "movetonext", "movetofirst", "getcolumnindex", "context", "intent",
    "environment", "file", "camera", "location",
}


def normalise(p: str) -> str:
    return p.strip().replace("android.permission.", "").upper()


def data_type_for(permission: str) -> str:
    entry = PERMISSION_CATALOG.get(normalise(permission))
    return entry[0] if entry else normalise(permission).lower()


def catalog_for_ui() -> list:
    return [{"permission": k, "data_type": v[0], "label": v[1]}
            for k, v in PERMISSION_CATALOG.items()]


def baseline_api_targets(permissions: list) -> list:
    out = []
    for p in permissions:
        entry = PERMISSION_CATALOG.get(normalise(p))
        if entry:
            out.append({"permission": normalise(p), "data_type": entry[0],
                        "identifiers": list(entry[2])})
    return out


def clean_api_targets(llm_targets: list, permissions: list) -> list:
    """Merge LLM targets with the baseline; drop over-generic identifiers."""
    merged = {}
    for t in baseline_api_targets(permissions) + list(llm_targets or []):
        perm = normalise(t.get("permission", ""))
        if not perm:
            continue
        slot = merged.setdefault(perm, {
            "permission": perm,
            "data_type": t.get("data_type") or data_type_for(perm),
            "identifiers": [],
        })
        for ident in t.get("identifiers", []):
            ident = str(ident).strip()
            if len(ident) < 5 or ident.lower() in _GENERIC:
                continue
            if ident not in slot["identifiers"]:
                slot["identifiers"].append(ident)
    return [t for t in merged.values() if t["identifiers"]]


# ── Trackers ─────────────────────────────────────────────────────────────────

_TRACKERS = None


def _load_trackers():
    global _TRACKERS
    if _TRACKERS is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "exodus_trackers.json")
        try:
            with open(path) as f:
                data = json.load(f)["trackers"]
            _TRACKERS = []
            for t in data.values():
                sig = (t.get("code_signature") or "").strip()
                if sig:
                    _TRACKERS.append((t["name"], t.get("website", ""),
                                      t.get("categories", ""), re.compile(sig)))
        except Exception:
            _TRACKERS = []
    return _TRACKERS


def detect_trackers(class_names) -> list:
    """class_names: Dalvik names (Lcom/foo/Bar;). Returns matched trackers."""
    dotted = ["" if not c else c[1:-1].replace("/", ".") for c in class_names]
    found = []
    for name, site, cats, rx in _load_trackers():
        hit = next((c for c in dotted if rx.search(c)), None)
        if hit:
            cats = re.sub(r"[\[\]']", "", cats)
            found.append({"name": name, "website": site, "categories": cats,
                          "example_class": hit})
    return sorted(found, key=lambda t: t["name"].lower())


# ── Frida template ───────────────────────────────────────────────────────────

def _java_class(c: str) -> str:
    c = c or ""
    if c.startswith("L") and c.endswith(";"):
        c = c[1:-1]
    return c.replace("/", ".")


def frida_template(app_name: str, package: str, flows: list,
                   static_sources: list) -> str:
    """Build a Frida script that hooks every method the analysis pointed at,
    plus the generic Android data APIs and common network sinks.
    Nothing in it depends on the LLM, so it always loads."""
    targets = []
    seen = set()
    for f in flows:
        for cls, meth, why in (
            (f.get("source_class"), f.get("source_method"),
             f"collects {f.get('data_type') or 'data'} (FlowDroid source)"),
            (f.get("dispatcher_class"), f.get("dispatcher_method"),
             "sends the data on (FlowDroid sink caller)"),
        ):
            cls = _java_class(cls)
            if cls and meth and not meth.startswith("<") and (cls, meth) not in seen:
                seen.add((cls, meth))
                targets.append((cls, meth, why))
    for s in static_sources[:40]:
        cls, meth = _java_class(s.get("source_class")), s.get("source_method")
        if cls and meth and not meth.startswith("<") and (cls, meth) not in seen:
            seen.add((cls, meth))
            targets.append((cls, meth,
                            f"uses {s.get('matched_api')} ({s.get('data_type')})"))

    app_hooks = ",\n".join(
        f'    [{json.dumps(c)}, {json.dumps(m)}, {json.dumps(w)}]'
        for c, m, w in targets) or ""

    return f"""// LoanWatch Frida script for {app_name} ({package})
// Generated from the static analysis report. Run with:
//   frida -U -f {package} -l this_file.js
// Every line printed by this script is prefixed with [LW] so it can be grepped.

function lw(tag, msg) {{
  console.log("[LW][" + tag + "] " + msg);
}}

function short(v) {{
  try {{
    if (v === null || v === undefined) return String(v);
    var s = v.toString();
    return s.length > 800 ? s.substring(0, 800) + "...(" + s.length + " chars)" : s;
  }} catch (e) {{ return "<unprintable>"; }}
}}

// App methods flagged by LoanWatch: [class, method, why]
var APP_TARGETS = [
{app_hooks}
];

function hookAll(clsName, methodName, tag) {{
  try {{
    var C = Java.use(clsName);
    if (!C[methodName]) {{ lw("miss", clsName + "." + methodName + " not found"); return; }}
    C[methodName].overloads.forEach(function (ov) {{
      ov.implementation = function () {{
        var args = [];
        for (var i = 0; i < arguments.length; i++) args.push(short(arguments[i]));
        var ret = ov.apply(this, arguments);
        lw(tag, clsName + "." + methodName + "(" + args.join(", ") + ") -> " + short(ret));
        return ret;
      }};
    }});
    lw("hooked", clsName + "." + methodName);
  }} catch (e) {{
    lw("error", clsName + "." + methodName + ": " + e);
  }}
}}

Java.perform(function () {{
  // 1. Which private data stores does the app open?
  try {{
    var CR = Java.use("android.content.ContentResolver");
    CR.query.overloads.forEach(function (ov) {{
      ov.implementation = function () {{
        var uri = short(arguments[0]);
        if (/contacts|call_log|sms|mms|media|calendar/i.test(uri)) {{
          lw("DATA-ACCESS", "ContentResolver.query " + uri);
          lw("stack", Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split("\\n").slice(1, 6).join(" <- "));
        }}
        return ov.apply(this, arguments);
      }};
    }});
  }} catch (e) {{ lw("error", "ContentResolver: " + e); }}

  // 2. Methods found by LoanWatch static / taint analysis
  APP_TARGETS.forEach(function (t) {{ hookAll(t[0], t[1], "APP " + t[2]); }});

  // 3. Where does data go? Common network sinks.
  try {{
    var URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function (u) {{
      lw("NET", "URL " + u);
      return this.$init(u);
    }};
  }} catch (e) {{ lw("error", "URL: " + e); }}
  try {{
    var RB = Java.use("okhttp3.Request$Builder");
    RB.build.implementation = function () {{
      var req = this.build();
      lw("NET", "OkHttp " + req.method() + " " + req.url());
      return req;
    }};
  }} catch (e) {{ lw("info", "OkHttp not present"); }}
  try {{
    var RBody = Java.use("okhttp3.RequestBody");
    RBody.create.overloads.forEach(function (ov) {{
      ov.implementation = function () {{
        lw("NET-BODY", short(arguments[arguments.length - 1]));
        return ov.apply(this, arguments);
      }};
    }});
  }} catch (e) {{ }}
  try {{
    var SM = Java.use("android.telephony.SmsManager");
    SM.sendTextMessage.overloads.forEach(function (ov) {{
      ov.implementation = function () {{
        lw("SMS-SEND", "to " + arguments[0] + ": " + short(arguments[2]));
        return ov.apply(this, arguments);
      }};
    }});
  }} catch (e) {{ }}
}});
"""
