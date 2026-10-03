#!/usr/bin/env python3
"""
LoanWatch web app — runs on your own computer.

    python3 web/app.py            # then open http://127.0.0.1:8765

Upload an APK and a lending policy; the page shows which prohibited
permissions the app declares, where in the code the data is read, whether
FlowDroid can trace it to the network, and gives you a Frida script for the
on-device test. Files never leave this computer except the policy text,
which is sent to Groq when an API key is set.
"""
import argparse
import os
import re
import sys
import threading
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from flask import Flask, abort, jsonify, render_template, request, send_from_directory  # noqa: E402

from web import runner  # noqa: E402

app = Flask(__name__, template_folder=os.path.join(HERE, "templates"),
            static_folder=os.path.join(HERE, "static"))
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024   # 1 GB uploads


def _safe_name(name, default):
    name = os.path.basename(name or "") or default
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]


def _job_or_404(job_id):
    job = runner.JOBS.get(job_id)
    if job is None:
        abort(404)
    return job


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    return jsonify(runner.tool_status())


@app.post("/api/key")
def save_key():
    key = (request.json or {}).get("key", "").strip()
    if not key:
        return jsonify({"error": "empty key"}), 400
    ok, msg = runner.check_groq_key(key)
    if ok is False:
        return jsonify({"error": msg}), 400
    runner.save_groq_key(key)
    return jsonify({"ok": True, "checked": ok is True, "message": msg})


@app.get("/api/key/check")
def check_key():
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        return jsonify({"ok": False, "message": "no key set"})
    ok, msg = runner.check_groq_key(key)
    return jsonify({"ok": ok, "message": msg})


@app.get("/api/jobs")
def jobs():
    return jsonify(runner.job_list())


@app.post("/api/jobs")
def create_job():
    apk = request.files.get("apk")
    if not apk or not apk.filename:
        return jsonify({"error": "Please choose an APK file."}), 400
    if not apk.filename.lower().endswith(".apk"):
        return jsonify({"error": "The app must be a single .apk file "
                                 "(for .xapk/.apks, extract base.apk first)."}), 400
    policy = request.files.get("policy")
    clause = request.form.get("clause", "").strip()
    options = {
        "groq_key": request.form.get("groq_key", "").strip(),
        "clause": int(clause) if clause.isdigit() and int(clause) > 0 else None,
        "jurisdiction": request.form.get("jurisdiction", "").strip()[:40],
        "apk_name": _safe_name(apk.filename, "app.apk"),
        "policy_name": _safe_name(policy.filename, "") if policy and policy.filename else "",
    }
    job = runner.create_job(None, None, options)
    job.apk_path = os.path.join(job.dir, _safe_name(apk.filename, "app.apk"))
    apk.save(job.apk_path)
    if policy and policy.filename:
        ext = os.path.splitext(policy.filename)[1].lower()
        if ext not in (".pdf", ".txt", ".md"):
            return jsonify({"error": "The policy must be a PDF or a .txt file."}), 400
        job.policy_path = os.path.join(job.dir, "policy" + ext)
        policy.save(job.policy_path)
    runner.start_policy_phase(job)
    return jsonify({"id": job.id})


@app.get("/api/jobs/<job_id>")
def job_state(job_id):
    job = _job_or_404(job_id)
    since = request.args.get("since", "0")
    return jsonify(job.public(int(since) if since.isdigit() else 0))


@app.post("/api/jobs/<job_id>/confirm")
def confirm(job_id):
    job = _job_or_404(job_id)
    if job.state != "awaiting_confirmation":
        return jsonify({"error": f"job is {job.state}"}), 409
    body = request.json or {}
    perms = [p for p in body.get("permissions", []) if isinstance(p, str)]
    include_google = bool(body.get("include_google", True))
    if not perms and not include_google:
        return jsonify({"error": "Tick at least one prohibited permission "
                                 "or the Google Play policy."}), 400
    runner.start_analysis_phase(job, perms, body.get("prohibited_data") or [],
                                bool(body.get("run_flowdroid", True)),
                                include_google=include_google,
                                expand_groups=bool(body.get("expand_groups", True)))
    return jsonify({"ok": True})


@app.get("/api/jobs/<job_id>/files/<name>")
def download(job_id, name):
    job = _job_or_404(job_id)
    allowed = {"report.json", "loanwatch_frida.js", "loanwatch_frida_ai.js",
               "icon.png", "icon.webp", "icon.jpg", "icon.jpeg"}
    if name not in allowed:
        abort(404)
    return send_from_directory(job.dir, name, as_attachment=not name.startswith("icon."))


def main():
    ap = argparse.ArgumentParser(description="LoanWatch web app")
    ap.add_argument("--port", type=int, default=int(os.environ.get("LOANWATCH_PORT", 8765)))
    ap.add_argument("--host", default=os.environ.get("LOANWATCH_HOST", "127.0.0.1"),
                    help="keep 127.0.0.1 unless you run it in Docker")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    runner.install_stdout_capture()
    runner.load_past_jobs()
    url = f"http://127.0.0.1:{args.port}"
    print(f"\n  LoanWatch is running at {url}\n  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
