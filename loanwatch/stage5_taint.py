"""
Stage 5: FlowDroid taint analysis

Builds a SourcesAndSinks.txt from Stage 4 results, runs FlowDroid,
and parses the XML output to return confirmed taint paths.

If FlowDroid is unavailable (--skip-flowdroid), returns Stage 4
sources directly as unconfirmed paths.
"""
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
import warnings
warnings.filterwarnings("ignore")


# ── Sinks ─────────────────────────────────────────────────────────────────────
NETWORK_SINKS = [
    # OkGo (lzy) — confirmed sink in EasyCash; execute(Callback) is the dispatch
    # point FlowDroid can reach without tracing through OkGo internals
    "<com.lzy.okgo.request.base.Request: void execute(com.lzy.okgo.callback.Callback)> -> _SINK_",
    "<com.lzy.okgo.OkGo: com.lzy.okgo.request.PostRequest post(java.lang.String)> -> _SINK_",
    "<com.lzy.okgo.request.PostRequest: okhttp3.Request generateRequest(okhttp3.RequestBody)> -> _SINK_",
    # OkHttp3 (underlying transport for OkGo, Retrofit, and many apps directly)
    "<okhttp3.OkHttpClient: okhttp3.Call newCall(okhttp3.Request)> -> _SINK_",
    "<okhttp3.Call: okhttp3.Response execute()> -> _SINK_",
    "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,java.lang.String)> -> _SINK_",
    "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,byte[])> -> _SINK_",
    "<okhttp3.FormBody$Builder: okhttp3.FormBody$Builder add(java.lang.String,java.lang.String)> -> _SINK_",
    # Retrofit2
    "<retrofit2.Call: okhttp3.Response execute()> -> _SINK_",
    "<retrofit2.Call: void enqueue(retrofit2.Callback)> -> _SINK_",
    # Volley
    "<com.android.volley.RequestQueue: com.android.volley.Request add(com.android.volley.Request)> -> _SINK_",
    "<com.android.volley.toolbox.StringRequest: void deliverResponse(java.lang.String)> -> _SINK_",
    # Standard Java network
    "<java.net.URLConnection: void connect()> -> _SINK_",
    "<java.net.URLConnection: java.io.InputStream getInputStream()> -> _BOTH_",
    "<java.net.URLConnection: java.io.OutputStream getOutputStream()> -> _SINK_",
    "<java.net.URL: java.io.InputStream openStream()> -> _BOTH_",
    "<java.net.URL: java.lang.Object getContent()> -> _BOTH_",
    "<java.net.URL: void set(java.lang.String,java.lang.String,int,java.lang.String,java.lang.String)> -> _SINK_",
    "<java.net.Socket: void connect(java.net.SocketAddress)> -> _SINK_",
    # SMS
    "<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)> -> _SINK_",
    "<android.telephony.SmsManager: void sendMultipartTextMessage(java.lang.String,java.lang.String,java.util.ArrayList,java.util.ArrayList,java.util.ArrayList)> -> _SINK_",
    # ContentResolver writes
    "<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)> -> _SINK_",
    "<android.content.ContentResolver: int delete(android.net.Uri,java.lang.String,java.lang.String[])> -> _SINK_",
    "<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])> -> _SINK_",
    # Shell execution
    "<java.lang.ProcessBuilder: java.lang.Process start()> -> _SINK_",
]

# ── Android API sources indexed by permission ─────────────────────────────────
# Use the actual Android API calls as sources (not app wrapper methods).
# FlowDroid tracks taint from the Cursor/value returned by these calls.
_ANDROID_API_SOURCES = {
    "READ_CONTACTS": [
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _SOURCE_",
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],android.os.Bundle,android.os.CancellationSignal)> -> _SOURCE_",
    ],
    "READ_CALL_LOG": [
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _SOURCE_",
    ],
    "READ_SMS": [
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _SOURCE_",
    ],
    "READ_EXTERNAL_STORAGE": [
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _SOURCE_",
        "<android.content.ContentResolver: android.content.res.AssetFileDescriptor openAssetFileDescriptor(android.net.Uri,java.lang.String)> -> _SOURCE_",
        "<android.provider.MediaStore$Images$Media: android.graphics.Bitmap getBitmap(android.content.ContentResolver,android.net.Uri)> -> _SOURCE_",
    ],
    "READ_MEDIA_IMAGES": [
        "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _SOURCE_",
    ],
    "READ_PHONE_STATE": [
        "<android.telephony.TelephonyManager: java.lang.String getDeviceId()> -> _SOURCE_",
        "<android.telephony.TelephonyManager: java.lang.String getSubscriberId()> -> _SOURCE_",
        "<android.telephony.TelephonyManager: java.lang.String getLine1Number()> -> _SOURCE_",
        "<android.telephony.TelephonyManager: java.lang.String getSimSerialNumber()> -> _SOURCE_",
        "<android.telephony.TelephonyManager: java.lang.String getImei()> -> _SOURCE_",
    ],
    "ACCESS_FINE_LOCATION": [
        "<android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String)> -> _SOURCE_",
        "<android.location.Location: double getLatitude()> -> _SOURCE_",
        "<android.location.Location: double getLongitude()> -> _SOURCE_",
    ],
    "ACCESS_COARSE_LOCATION": [
        "<android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String)> -> _SOURCE_",
    ],
    "CAMERA": [
        "<android.hardware.Camera: android.hardware.Camera open()> -> _SOURCE_",
    ],
    "RECORD_AUDIO": [
        "<android.media.MediaRecorder: void start()> -> _SOURCE_",
    ],
}


def _dalvik_to_flowdroid(dalvik_class: str) -> str:
    """Convert Lcom/example/Foo; → com.example.Foo"""
    return dalvik_class.lstrip("L").rstrip(";").replace("/", ".")


def _dalvik_type_to_java(t: str) -> str:
    """Convert a single Dalvik type descriptor to Java class name."""
    primitives = {"V": "void", "Z": "boolean", "B": "byte", "C": "char",
                  "S": "short", "I": "int", "J": "long", "F": "float", "D": "double"}
    if t in primitives:
        return primitives[t]
    if t.startswith("["):
        return _dalvik_type_to_java(t[1:]) + "[]"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t


def _parse_descriptor(descriptor: str):
    """Parse Dalvik method descriptor e.g. '(Landroid/content/Context;I)V'
       Returns (return_type_java, [param_types_java])."""
    if not descriptor or "(" not in descriptor:
        return "void", []
    params_str = descriptor[descriptor.index("(") + 1: descriptor.index(")")]
    ret_str    = descriptor[descriptor.index(")") + 1:]

    params = []
    i = 0
    while i < len(params_str):
        if params_str[i] == "L":
            end = params_str.index(";", i)
            params.append(_dalvik_type_to_java(params_str[i:end + 1]))
            i = end + 1
        elif params_str[i] == "[":
            j = i + 1
            while j < len(params_str) and params_str[j] == "[":
                j += 1
            if params_str[j] == "L":
                end = params_str.index(";", j)
                params.append(_dalvik_type_to_java(params_str[i:end + 1]))
                i = end + 1
            else:
                params.append(_dalvik_type_to_java(params_str[i:j + 1]))
                i = j + 1
        else:
            params.append(_dalvik_type_to_java(params_str[i]))
            i += 1

    return _dalvik_type_to_java(ret_str), params


def _build_sources_sinks(sources: list) -> str:
    """Build FlowDroid SourcesAndSinks.txt using standard Android API sources.

    Uses Android API methods (ContentResolver.query, TelephonyManager.getDeviceId,
    etc.) as sources rather than app-specific wrapper methods.  FlowDroid can
    cleanly taint the Cursor/value returned by these calls and propagate it to
    the network sink.  Fallback to app-specific methods when no mapping exists.
    """
    lines = ["# Auto-generated by LoanWatch Stage 5", ""]
    lines.append("# Sources (Android API methods for violated permissions)")

    # Collect unique permissions from Stage 4 sources
    permissions = set()
    for s in sources:
        perm = s.get("permission", "").replace("android.permission.", "").upper()
        if perm:
            permissions.add(perm)

    seen = set()
    for perm in sorted(permissions):
        for sig in _ANDROID_API_SOURCES.get(perm, []):
            if sig not in seen:
                seen.add(sig)
                lines.append(sig)

    # Fallback: if no permission mapping, use app-specific method signatures.
    # ONLY include methods with a non-void return type — FlowDroid taints the
    # return value of _SOURCE_ methods.  A void method produces nothing to taint
    # at the call site, so including it silently gives 0 results.
    if not seen:
        lines.append("# Fallback: app-specific source methods (non-void only)")
        for s in sources:
            cls        = _dalvik_to_flowdroid(s["source_class"])
            method     = s["source_method"]
            descriptor = s.get("source_descriptor", "")
            ret, params = _parse_descriptor(descriptor)
            if ret == "void":
                continue   # void return → nothing to taint; skip
            params_str = ", ".join(params)
            lines.append(f"<{cls}: {ret} {method}({params_str})> -> _SOURCE_")

    lines.append("")
    lines.append("# Sinks")
    for sink in NETWORK_SINKS:
        lines.append(sink)
    return "\n".join(lines)


def _parse_method_sig(sig: str):
    """Parse '<ClassName: ReturnType methodName(params)>' → ('ClassName', 'methodName')"""
    m = re.match(r'<([^:]+):\s+\S+\s+(\w+)\(', sig)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", ""


def _extract_params_from_sig(sig: str) -> list:
    """Extract parameter types from '<Class: RetType method(param1,param2)>'.
    e.g. '<ji: java.util.List sd(android.content.Context)>' → ['android.content.Context']
    Used to generate correct Frida overload() calls."""
    m = re.search(r'\w+\(([^)]*)\)', sig)
    if m and m.group(1).strip():
        return [p.strip() for p in m.group(1).split(',') if p.strip()]
    return []


def _parse_flowdroid_xml(xml_path: str) -> list:
    """Parse FlowDroid 2.x results XML into a list of taint paths.

    FlowDroid 2.x uses Method= and Statement= attributes (not ClassName/MethodName).
    The Source Method= attribute contains the APP method where the API is called.
    The Sink Statement= attribute contains the actual network call being made.
    """
    paths = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for result in root.iter("Result"):
            sink_elem = result.find("Sink")
            sources_cont = result.find("Sources")
            source_elems = (sources_cont.findall("Source")
                            if sources_cont is not None else [])
            if not source_elems:
                src = result.find("Source")
                if src is not None:
                    source_elems = [src]

            if sink_elem is None or not source_elems:
                continue

            # Sink: Method="<zn: void NC(zn$oE)>"
            # Statement="virtualinvoke $r15.<Request: void execute(Callback)>($r17)"
            sink_method_sig = sink_elem.get("Method", "")
            sink_class, sink_method = _parse_method_sig(sink_method_sig)
            stmt = sink_elem.get("Statement", "")
            # Extract the actual network call class/method from the statement
            net_match = re.search(r'<([^:]+):\s+\S+\s+(\w+)\(', stmt)
            net_class  = net_match.group(1).strip() if net_match else sink_class
            net_method = net_match.group(2).strip() if net_match else sink_method

            # Dispatcher params from Sink.Method e.g. "<zn: void NC(zn$oE)>"
            dispatcher_params = _extract_params_from_sig(sink_method_sig)

            for source_elem in source_elems:
                # Source Method="<ji: java.util.List sd(android.content.Context)>"
                src_sig = source_elem.get("Method", "")
                src_class, src_method = _parse_method_sig(src_sig)
                # Extract exact param types from the signature for Frida overload() calls
                src_params = _extract_params_from_sig(src_sig)
                paths.append({
                    "source_class":        src_class,
                    "source_method":       src_method,
                    "source_params":       src_params,         # e.g. ['android.content.Context']
                    "dispatcher_class":    sink_class,         # app method that calls network (e.g. zn)
                    "dispatcher_method":   sink_method,        # e.g. NC
                    "dispatcher_params":   dispatcher_params,  # e.g. ['zn$oE']
                    "sink_class":          net_class,          # actual network class (e.g. Request)
                    "sink_method":         net_method,         # e.g. execute
                    "statement":           stmt,
                })
    except Exception as e:
        paths.append({"error": f"XML parse failed: {e}"})
    return paths


def run(apk_path: str, sources: list, flowdroid_jar: str = "",
        platforms_dir: str = "", verbose: bool = True) -> dict:
    """
    sources      : list from Stage 4
    flowdroid_jar: path to soot-infoflow-cmd-jar-with-dependencies.jar
                   (empty string = skip FlowDroid)

    Returns:
        {
          "ran_flowdroid": True/False,
          "confirmed_sources": [   # methods confirmed to reach network
            {source_class, source_method, sink_class, sink_method, ...}
          ]
        }
    """
    if not sources:
        if verbose:
            print("[Stage 5] No sources from Stage 4 — skipping taint analysis.")
        return {"ran_flowdroid": False, "confirmed_sources": []}

    if not flowdroid_jar or not os.path.exists(flowdroid_jar):
        if verbose:
            print("[Stage 5] FlowDroid JAR not found — using Stage 4 sources directly.")
        confirmed = [
            {
                "source_class":  s["source_class"],
                "source_method": s["source_method"],
                "sink_class":    "network",
                "sink_method":   "N/A (unconfirmed — FlowDroid not run)",
                "permission":    s["permission"],
                "data_type":     s["data_type"],
                "matched_api":   s["matched_api"],
            }
            for s in sources
        ]
        return {"ran_flowdroid": False, "confirmed_sources": confirmed}

    # ── Build SourcesAndSinks.txt ─────────────────────────────────────────────
    if verbose:
        print("[Stage 5] Building SourcesAndSinks.txt from Android API sources...")

    ss_content = _build_sources_sinks(sources)
    src_count  = sum(1 for l in ss_content.splitlines() if "_SOURCE_" in l)

    work_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flowdroid_work")
    os.makedirs(work_dir, exist_ok=True)
    ss_file  = os.path.join(work_dir, "SourcesAndSinks.txt")
    out_file = os.path.join(work_dir, "results.xml")

    if os.path.exists(out_file):
        os.remove(out_file)

    with open(ss_file, "w") as f:
        f.write(ss_content)

    if verbose:
        print(f"[Stage 5] SourcesAndSinks.txt ({src_count} API sources + {len(NETWORK_SINKS)} sinks)")

    plat = platforms_dir or os.path.expanduser("~/Library/Android/sdk/platforms")

    cmd = [
        "java", "-Xmx8g", "-jar", flowdroid_jar,
        "-a", os.path.abspath(apk_path),
        "-p", plat,
        "-s", ss_file,
        "-o", out_file,
        "-dt", "300",     # data flow timeout per method
        "-ct", "300",     # call graph construction timeout
        "-d",             # enable data flow tracking
        "-rt", "480",     # total result timeout (seconds)
    ]

    if verbose:
        print("[Stage 5] Running FlowDroid...")

    import threading

    stdout_lines = []
    stderr_lines = []
    timed_out    = [False]

    def _stream(pipe, store, prefix):
        """Read pipe line-by-line, print immediately, and save."""
        try:
            for raw in iter(pipe.readline, ""):
                line = raw.rstrip()
                store.append(line)
                if verbose and line.strip():
                    print(f"   {prefix} {line}", flush=True)
        except Exception:
            pass
        finally:
            pipe.close()

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        t_out = threading.Thread(target=_stream,
                                 args=(proc.stdout, stdout_lines, "[fd]"),
                                 daemon=True)
        t_err = threading.Thread(target=_stream,
                                 args=(proc.stderr, stderr_lines, "[fd-err]"),
                                 daemon=True)
        t_out.start(); t_err.start()

        try:
            proc.wait(timeout=500)
        except subprocess.TimeoutExpired:
            timed_out[0] = True
            proc.kill()

        t_out.join(timeout=5); t_err.join(timeout=5)

        if verbose and proc.returncode not in (None, 0):
            print(f"[Stage 5] FlowDroid exit code {proc.returncode}")

    except Exception as e:
        if verbose:
            print(f"[Stage 5] Failed to launch FlowDroid: {e}")
        timed_out[0] = True

    if timed_out[0]:
        if verbose:
            print("[Stage 5] FlowDroid timed out — falling back to Stage 4 sources.")
        return {"ran_flowdroid": False, "confirmed_sources": [
            {"source_class": s["source_class"], "source_method": s["source_method"],
             "sink_class": "network", "sink_method": "timeout",
             "permission": s["permission"], "data_type": s["data_type"]}
            for s in sources
        ]}

    if not os.path.exists(out_file):
        if verbose:
            print("[Stage 5] No output file — returning Stage 4 sources.")
        return {"ran_flowdroid": False, "confirmed_sources": [
            {"source_class": s["source_class"], "source_method": s["source_method"],
             "sink_class": "network", "sink_method": "no_flowdroid_output",
             "permission": s["permission"], "data_type": s["data_type"],
             "matched_api": s.get("matched_api", "")}
            for s in sources
        ]}

    paths = _parse_flowdroid_xml(out_file)

    if verbose:
        print(f"[Stage 5] FlowDroid found {len(paths)} taint path(s).")
        for p in paths:
            print(f"   • {p.get('source_class', '')}→{p.get('source_method', '')} "
                  f"  ──►  {p.get('sink_class', '')}→{p.get('sink_method', '')}")

    # Enrich with permission/data_type from Stage 4 sources
    # source_class in FlowDroid results is the app class (e.g. "ji"),
    # Stage 4 stores it as "Lji;" — normalise for lookup.
    source_meta = {(s["source_class"].replace("/", ".").lstrip("L").rstrip(";"),
                    s["source_method"]): s
                   for s in sources}

    confirmed = []
    for p in paths:
        if "error" in p:
            continue
        meta = source_meta.get((p["source_class"], p["source_method"]), {})
        confirmed.append({**p, **{k: meta.get(k, "") for k in
                                  ("permission", "data_type", "matched_api")}})

    return {"ran_flowdroid": True, "confirmed_sources": confirmed}
