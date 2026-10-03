"""
Job runner for the LoanWatch web app.

A job runs in two phases so the person using the page can check the AI's
reading of the policy before anything is scored against it:

  Phase A  (start_policy_phase)
     Stage 1  policy → prohibited data + permissions   (LLM, or manual)
     load APK with Androguard (manifest + bytecode)
     → state "awaiting_confirmation"

  Phase B  (start_analysis_phase, after the user confirms the permission list)
     Stage 2  manifest audit
     trackers  Exodus signatures
     Stage 3  permissions → API identifiers            (LLM + built-in map)
     Stage 4  Androguard bytecode scan
     Stage 5  FlowDroid taint analysis                 (if installed)
     Stage 6  Frida script for the dynamic test        (template + LLM)
     → state "done"

Stage modules print progress; everything printed while a job is active is
captured into that job's log and streamed to the browser.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
LOANWATCH_DIR = os.path.dirname(HERE)
if LOANWATCH_DIR not in sys.path:
    sys.path.insert(0, LOANWATCH_DIR)

import stage1_policy   # noqa: E402
import stage2_audit    # noqa: E402
import stage3_api_map  # noqa: E402
import stage4_static   # noqa: E402
import stage5_taint    # noqa: E402
import stage6_frida    # noqa: E402

from web import baseline  # noqa: E402

JOBS_DIR = os.environ.get("LOANWATCH_JOBS_DIR", os.path.join(HERE, "jobs"))

STAGES = [
    ("policy",   "Read the policy"),
    ("apk",      "Open the APK"),
    ("manifest", "Check declared permissions"),
    ("trackers", "Look for tracking SDKs"),
    ("api_map",  "Map permissions to Android APIs"),
    ("static",   "Find the code that reads the data"),
    ("taint",    "Trace data to the network (FlowDroid)"),
    ("frida",    "Prepare the on-device test script"),
]


# ── Configuration / tool discovery ───────────────────────────────────────────

def _load_dotenv():
    """Read loanwatch/.env (KEY=VALUE lines) into os.environ if present."""
    path = os.path.join(LOANWATCH_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def save_groq_key(key: str):
    path = os.path.join(LOANWATCH_DIR, ".env")
    lines = []
    if os.path.exists(path):
        with open(path) as f:
            lines = [l for l in f.read().splitlines()
                     if not l.startswith("GROQ_API_KEY=")]
    lines.append(f"GROQ_API_KEY={key}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    os.environ["GROQ_API_KEY"] = key


def _default_java_mem() -> str:
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        gb = max(2, min(12, int(total / 2**30 * 0.6)))
        return f"{gb}g"
    except (ValueError, OSError, AttributeError):
        return "4g"


def _platform_candidates():
    env = os.environ.get("LOANWATCH_PLATFORMS")
    if env:
        yield env
    yield os.path.join(LOANWATCH_DIR, "lib", "platforms")
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(var):
            yield os.path.join(os.environ[var], "platforms")
    home = os.path.expanduser("~")
    yield os.path.join(home, "Library", "Android", "sdk", "platforms")
    yield os.path.join(home, "Android", "Sdk", "platforms")
    yield os.path.join(home, "AppData", "Local", "Android", "Sdk", "platforms")


def _platform_levels(path):
    levels = []
    if path and os.path.isdir(path):
        for d in os.listdir(path):
            m = re.match(r"android-(\d+)$", d)
            if m and os.path.isfile(os.path.join(path, d, "android.jar")):
                levels.append(int(m.group(1)))
    return sorted(levels)


def tool_status() -> dict:
    jar = os.environ.get("LOANWATCH_FLOWDROID_JAR",
                         os.path.join(LOANWATCH_DIR, "lib", "flowdroid.jar"))
    platforms, levels = "", []
    for cand in _platform_candidates():
        lv = _platform_levels(cand)
        if lv:
            platforms, levels = cand, lv
            break

    java = shutil.which("java")
    java_version = ""
    if java:
        try:
            out = subprocess.run([java, "-version"], capture_output=True,
                                 text=True, timeout=20)
            m = re.search(r'version "([^"]+)"', out.stderr + out.stdout)
            java_version = m.group(1) if m else "unknown"
        except Exception:
            java_version = "unknown"

    flowdroid_ready = bool(java and os.path.isfile(jar) and levels)
    return {
        "groq_key":        bool(os.environ.get("GROQ_API_KEY")),
        "java":            java_version or "",
        "flowdroid_jar":   jar if os.path.isfile(jar) else "",
        "platforms_dir":   platforms,
        "platform_levels": levels,
        "flowdroid_ready": flowdroid_ready,
        "java_mem":        os.environ.get("LOANWATCH_JAVA_MEM", _default_java_mem()),
    }


# ── stdout capture ───────────────────────────────────────────────────────────

class _Tee(io.TextIOBase):
    """Sends writes to the real stdout and to the active job's log."""

    def __init__(self, real):
        self.real = real
        self.job = None
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, s):
        try:
            self.real.write(s)
        except Exception:
            pass
        job = self.job
        if job is not None:
            with self._lock:
                self._buf += s
                while "\n" in self._buf:
                    line, self._buf = self._buf.split("\n", 1)
                    job.log(line)
        return len(s)

    def flush(self):
        try:
            self.real.flush()
        except Exception:
            pass


_tee = None
_run_lock = threading.Lock()   # one heavy analysis at a time (FlowDroid is RAM-hungry)


def install_stdout_capture():
    global _tee
    if _tee is None:
        _tee = _Tee(sys.stdout)
        sys.stdout = _tee
    # Androguard 4 logs very verbosely through loguru; keep warnings only.
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="ERROR")
    except Exception:
        pass


# ── Jobs ─────────────────────────────────────────────────────────────────────

class Job:
    def __init__(self, apk_path, policy_path, options, job_id=None, job_dir=None):
        self.id = job_id or uuid.uuid4().hex[:12]
        self.dir = job_dir or os.path.join(JOBS_DIR, self.id)
        os.makedirs(self.dir, exist_ok=True)
        self.apk_path = apk_path
        self.policy_path = policy_path
        self.options = options          # groq_key is held in memory only
        self.created = time.time()
        self.state = "queued"
        self.error = ""
        self.stages = {k: {"status": "pending", "note": ""} for k, _ in STAGES}
        self.logs = []
        self.stage1 = None
        self.apk_info = None
        self.report = None
        self._apk = self._analysis = None
        self._lock = threading.Lock()

    # -- helpers --
    def log(self, line):
        with self._lock:
            self.logs.append(line)

    def set_stage(self, key, status, note=""):
        self.stages[key] = {"status": status, "note": note}
        label = dict(STAGES)[key]
        self.log(f"── {label}: {status}{(' — ' + note) if note else ''}")

    @property
    def groq_key(self):
        return self.options.get("groq_key") or os.environ.get("GROQ_API_KEY", "")

    def public(self, since=0):
        return {
            "id": self.id,
            "state": self.state,
            "error": self.error,
            "stages": [{"key": k, "label": l, **self.stages[k]} for k, l in STAGES],
            "logs": self.logs[since:],
            "log_count": len(self.logs),
            "stage1": self.stage1,
            "apk_info": self.apk_info,
            "report": self.report,
            "has_llm": bool(self.groq_key),
        }


JOBS = {}


def create_job(apk_path, policy_path, options) -> Job:
    job = Job(apk_path, policy_path, options)
    JOBS[job.id] = job
    return job


def load_past_jobs():
    """Make finished reports from earlier sessions viewable again."""
    if not os.path.isdir(JOBS_DIR):
        return
    for jid in os.listdir(JOBS_DIR):
        rp = os.path.join(JOBS_DIR, jid, "report.json")
        if jid in JOBS or not os.path.isfile(rp):
            continue
        try:
            with open(rp) as f:
                report = json.load(f)
        except Exception:
            continue
        job = Job(None, None, {}, job_id=jid, job_dir=os.path.join(JOBS_DIR, jid))
        job.state = "done"
        job.report = report
        job.stage1 = report.get("policy")
        job.apk_info = report.get("app")
        job.created = report.get("created", os.path.getmtime(rp))
        for k, _ in STAGES:
            job.stages[k] = report.get("stages", {}).get(k, {"status": "done", "note": ""})
        JOBS[jid] = job


def job_list():
    out = []
    for j in sorted(JOBS.values(), key=lambda j: -j.created):
        app = j.apk_info or {}
        out.append({
            "id": j.id, "state": j.state, "created": j.created,
            "app_name": app.get("app_name", ""), "package": app.get("package", ""),
            "verdict": (j.report or {}).get("verdict", ""),
        })
    return out


def _run_in_thread(job, fn):
    def target():
        with _run_lock:
            _tee.job = job
            try:
                fn(job)
            except Exception as e:
                job.state = "error"
                job.error = f"{type(e).__name__}: {e}"
                job.log(traceback.format_exc())
                for k, v in job.stages.items():
                    if v["status"] == "running":
                        job.stages[k] = {"status": "failed", "note": str(e)[:200]}
            finally:
                print("", flush=True)
                _tee.job = None
    threading.Thread(target=target, daemon=True).start()


# ── Phase A ──────────────────────────────────────────────────────────────────

def start_policy_phase(job: Job):
    job.state = "reading_policy"
    _run_in_thread(job, _policy_phase)


def _policy_phase(job: Job):
    opts = job.options
    # Stage 1
    job.set_stage("policy", "running")
    s1 = {"prohibited_data": [], "permissions": [], "evidence": [],
          "clause_text": "", "source": "manual"}
    if job.policy_path:
        try:
            text = stage1_policy._extract_pdf_text(job.policy_path)
            s1["clause_text"] = (stage1_policy._find_clause(text, opts["clause"])
                                 if opts.get("clause") else
                                 stage1_policy._relevant_excerpts(text))
        except Exception as e:
            job.set_stage("policy", "failed", f"could not read the policy file: {e}")
            s1["clause_text"] = ""
    if job.policy_path and job.groq_key and job.stages["policy"]["status"] != "failed":
        try:
            r = stage1_policy.run(job.policy_path, job.groq_key,
                                  opts.get("clause") or None, True,
                                  jurisdiction=opts.get("jurisdiction", ""))
            s1.update(r)
            s1["source"] = "ai"
            job.set_stage("policy", "done",
                          f"AI found {len(s1['permissions'])} prohibited permission(s)")
        except Exception as e:
            job.set_stage("policy", "failed",
                          f"AI step failed ({type(e).__name__}: {str(e)[:160]}). "
                          "Pick the prohibited data by hand below.")
    elif job.stages["policy"]["status"] == "running":
        why = "no policy uploaded" if not job.policy_path else "no Groq API key"
        job.set_stage("policy", "skipped", f"{why} — pick the prohibited data by hand below")
    s1["catalog"] = baseline.catalog_for_ui()
    s1["presets"] = baseline.PRESETS
    job.stage1 = s1

    # Load the APK once; Stages 2 and 4 reuse it.
    job.set_stage("apk", "running", "Androguard is decompiling — large apps take a few minutes")
    from androguard.misc import AnalyzeAPK
    t0 = time.time()
    apk, _, analysis = AnalyzeAPK(job.apk_path)
    job._apk, job._analysis = apk, analysis
    declared = sorted(apk.get_permissions())
    job.apk_info = {
        "app_name": apk.get_app_name(),
        "package": apk.get_package(),
        "version": apk.get_androidversion_name(),
        "target_sdk": apk.get_target_sdk_version(),
        "min_sdk": apk.get_min_sdk_version(),
        "declared_permissions": declared,
        "declared_short": [baseline.normalise(p) for p in declared],
        "file_name": opts.get("apk_name", os.path.basename(job.apk_path)),
    }
    job.set_stage("apk", "done", f"{job.apk_info['app_name']} ({job.apk_info['package']}) "
                                 f"in {time.time() - t0:.0f}s")
    job.state = "awaiting_confirmation"


# ── Phase B ──────────────────────────────────────────────────────────────────

def start_analysis_phase(job: Job, permissions, prohibited_data, run_flowdroid=True):
    perms = list(dict.fromkeys(baseline.normalise(p) for p in permissions if p.strip()))
    job.stage1["permissions"] = perms
    job.stage1["prohibited_data"] = prohibited_data or sorted(
        {baseline.data_type_for(p) for p in perms})
    job.options["run_flowdroid"] = run_flowdroid
    job.state = "running"
    _run_in_thread(job, _analysis_phase)


def _dalvik_to_java(c):
    return (c or "").lstrip("L").rstrip(";").replace("/", ".")


def _analysis_phase(job: Job):
    s1 = job.stage1
    perms = s1["permissions"]
    report = {
        "created": job.created,
        "app": job.apk_info,
        "policy": {k: s1.get(k) for k in
                   ("permissions", "prohibited_data", "evidence", "clause_text", "source")},
        "policy_file": job.options.get("policy_name", ""),
    }

    # Stage 2 — manifest
    job.set_stage("manifest", "running")
    s2 = stage2_audit.run(job.apk_path, perms, True, apk=job._apk)
    report["manifest"] = s2
    job.set_stage("manifest", "done",
                  f"{len(s2['matched_permissions'])} prohibited permission(s) declared")

    # Trackers
    job.set_stage("trackers", "running")
    classes = [c.name for c in job._analysis.get_classes() if not c.is_external()]
    trackers = baseline.detect_trackers(classes)
    report["trackers"] = trackers
    job.set_stage("trackers", "done", f"{len(trackers)} tracker SDK(s) found")

    matched_short = [baseline.normalise(p) for p in s2["matched_permissions"]]
    s4 = {"sources": []}
    s5 = {"ran_flowdroid": False, "confirmed_sources": []}
    report["api_targets"] = []

    if not s2["violating"]:
        for k in ("api_map", "static", "taint"):
            job.set_stage(k, "skipped", "no prohibited permission is declared")
    else:
        # Stage 3 — permissions → API identifiers
        job.set_stage("api_map", "running")
        llm_targets, note = [], "built-in map"
        if job.groq_key:
            try:
                r = stage3_api_map.run(matched_short, s1["prohibited_data"],
                                       job.groq_key, True)
                llm_targets = r.get("api_targets", [])
                note = "AI + built-in map"
            except Exception as e:
                note = f"AI step failed ({type(e).__name__}); used built-in map"
        targets = baseline.clean_api_targets(llm_targets, matched_short)
        report["api_targets"] = targets
        job.set_stage("api_map", "done", note)

        # Stage 4 — bytecode scan
        job.set_stage("static", "running")
        s4 = stage4_static.run(job.apk_path, targets, True, analysis=job._analysis)
        job.set_stage("static", "done", f"{len(s4['sources'])} place(s) in the code")

        # Stage 5 — FlowDroid
        tools = tool_status()
        if not job.options.get("run_flowdroid", True):
            job.set_stage("taint", "skipped", "turned off for this run")
        elif not tools["flowdroid_ready"]:
            job.set_stage("taint", "skipped",
                          "FlowDroid / Java / android.jar not installed (run setup_tools.py)")
        elif not s4["sources"]:
            job.set_stage("taint", "skipped", "no code locations to trace")
        else:
            job.set_stage("taint", "running",
                          f"can take up to ~8 minutes (heap {tools['java_mem']})")
            s5 = stage5_taint.run(job.apk_path, s4["sources"],
                                  flowdroid_jar=tools["flowdroid_jar"],
                                  platforms_dir=tools["platforms_dir"], verbose=True,
                                  work_dir=os.path.join(job.dir, "flowdroid"),
                                  java_mem=tools["java_mem"])
            if s5["ran_flowdroid"]:
                job.set_stage("taint", "done",
                              f"{len(s5['confirmed_sources'])} source→sink path(s)")
            else:
                job.set_stage("taint", "failed",
                              "FlowDroid did not finish (timeout or error); see log")

    report["static_sources"] = s4["sources"]
    report["flowdroid"] = {
        "ran": s5["ran_flowdroid"],
        "flows": s5["confirmed_sources"] if s5["ran_flowdroid"] else [],
    }

    # Stage 6 — script for the on-device (dynamic) test
    job.set_stage("frida", "running")
    flows = report["flowdroid"]["flows"]
    app = job.apk_info
    script = baseline.frida_template(app["app_name"], app["package"], flows, s4["sources"])
    with open(os.path.join(job.dir, "loanwatch_frida.js"), "w") as f:
        f.write(script)
    report["frida_files"] = ["loanwatch_frida.js"]
    note = "template script ready"
    ai_input = flows or s4["sources"]   # as in main.py: static sources when no flow
    if job.groq_key and ai_input:
        try:
            s6 = stage6_frida.run(ai_input, app["app_name"], app["package"],
                                  job.groq_key, True)
            with open(os.path.join(job.dir, "loanwatch_frida_ai.js"), "w") as f:
                f.write(s6["frida_script"])
            report["frida_files"].append("loanwatch_frida_ai.js")
            note = "template + AI-written scripts ready"
        except Exception as e:
            note = f"template ready (AI script failed: {type(e).__name__})"
    job.set_stage("frida", "done", note)

    # Summary in plain language
    report["verdict"] = "VIOLATING" if s2["violating"] else "COMPLIANT"
    report["summary"] = _summary(report, perms)
    report["stages"] = job.stages
    job.report = report
    with open(os.path.join(job.dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    job.state = "done"
    job._apk = job._analysis = None   # free memory


def _summary(report, perms) -> list:
    app = report["app"]
    m = report["manifest"]["matched_permissions"]
    out = []
    if not m:
        out.append(f"{app['app_name']} does not declare any of the {len(perms)} "
                   "permissions this policy prohibits.")
    else:
        out.append(f"{app['app_name']} declares {len(m)} of the {len(perms)} prohibited "
                   f"permissions: {', '.join(baseline.normalise(p) for p in m)}.")
        by_type = {}
        for s in report["static_sources"]:
            by_type[s["data_type"]] = by_type.get(s["data_type"], 0) + 1
        if by_type:
            out.append("Code that accesses this data was found: " + ", ".join(
                f"{t} ({n} location{'s' if n != 1 else ''})" for t, n in by_type.items()) + ".")
        else:
            out.append("No code calling the matching Android APIs was found in the Java/Kotlin "
                       "bytecode (the app may use native code, reflection or packing).")
        fd = report["flowdroid"]
        if fd["ran"]:
            if fd["flows"]:
                out.append(f"FlowDroid traced {len(fd['flows'])} path(s) where this data "
                           "reaches a network or other output call.")
            else:
                out.append("FlowDroid found no complete path from the data to the network. "
                           "That does not prove the data is not sent; confirm on a device.")
        else:
            out.append("Data-flow tracing was not run, so transmission is not confirmed "
                       "statically; confirm on a device with the Frida script.")
    if report["trackers"]:
        out.append(f"{len(report['trackers'])} third-party tracking SDK(s) are embedded.")
    return out
