#!/usr/bin/env python3
"""
Download the analysis tools LoanWatch needs into loanwatch/lib/:

  lib/flowdroid.jar                    FlowDroid command-line (Maven Central)
  lib/platforms/android-NN/android.jar Android SDK platform (Google), for FlowDroid

Java 11+ must be installed separately (e.g. https://adoptium.net).
Safe to re-run; existing files are kept unless --force is given.

    python3 setup_tools.py            # FlowDroid + latest Android platform
    python3 setup_tools.py --api 34   # a specific platform level
"""
import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "lib")

FLOWDROID_VERSION = "2.15.1"
FLOWDROID_URL = ("https://repo1.maven.org/maven2/de/fraunhofer/sit/sse/flowdroid/"
                 "soot-infoflow-cmd/{v}/soot-infoflow-cmd-{v}-jar-with-dependencies.jar")
GOOGLE_REPO = "https://dl.google.com/android/repository/"
SABLE_RAW = "https://raw.githubusercontent.com/Sable/android-platforms/master/android-{api}/android.jar"


def fetch(url, what):
    print(f"  downloading {what}\n    {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "loanwatch-setup"})
    with urllib.request.urlopen(req, timeout=120) as r:
        total = int(r.headers.get("Content-Length") or 0)
        buf, done = io.BytesIO(), 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            buf.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r    {done >> 20} / {total >> 20} MB", end="", flush=True)
        print()
        return buf.getvalue()


def check_java():
    java = shutil.which("java")
    if not java:
        print("✗ Java not found. Install Java 11 or newer (https://adoptium.net), "
              "then re-run. The web app still works without it, but FlowDroid is skipped.")
        return False
    out = subprocess.run([java, "-version"], capture_output=True, text=True)
    m = re.search(r'version "(\d+)', out.stderr + out.stdout)
    major = int(m.group(1)) if m else 0
    if major == 1:        # "1.8.0_x" style
        major = 8
    ok = major >= 11
    print(f"{'✓' if ok else '✗'} Java {major} found{'' if ok else ' — FlowDroid ' + FLOWDROID_VERSION + ' needs Java 11+'}")
    return ok


def get_flowdroid(force):
    dest = os.path.join(LIB, "flowdroid.jar")
    if os.path.exists(dest) and not force:
        print(f"✓ FlowDroid already present: {dest}")
        return
    url = FLOWDROID_URL.format(v=FLOWDROID_VERSION)
    data = fetch(url, f"FlowDroid {FLOWDROID_VERSION}")
    sha = fetch(url + ".sha1", "checksum").decode().split()[0].strip()
    if hashlib.sha1(data).hexdigest() != sha:
        sys.exit("✗ FlowDroid checksum mismatch; download corrupted, try again.")
    with open(dest, "wb") as f:
        f.write(data)
    print(f"✓ FlowDroid saved to {dest}")


def _google_platform_zip(api):
    """Find the platform zip for an API level (or the newest) in Google's SDK index."""
    xml = fetch(GOOGLE_REPO + "repository2-3.xml", "Android SDK index").decode("utf-8", "ignore")
    found = {}
    for m in re.finditer(r'<remotePackage path="platforms;android-(\d+)(?:-ext\d+)?">(.*?)</remotePackage>',
                         xml, re.S):
        level, body = int(m.group(1)), m.group(2)
        if "<channelRef ref=\"channel-0\"/>" not in body:
            continue   # skip previews
        u = re.search(r"<url>(platform-[^<]+\.zip)</url>", body)
        if u:
            found.setdefault(level, u.group(1))
    if not found:
        return None, None
    level = api if api in found else max(found)
    return level, GOOGLE_REPO + found[level]


def get_platform(api, force):
    pdir = os.path.join(LIB, "platforms")
    existing = [d for d in os.listdir(pdir)] if os.path.isdir(pdir) else []
    if existing and not force and not api:
        print(f"✓ Android platform(s) already present: {', '.join(sorted(existing))}")
        return
    level, url, jar = None, None, None
    try:
        level, url = _google_platform_zip(api)
        if url:
            data = fetch(url, f"Android platform {level} (Google)")
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                name = next(n for n in z.namelist() if n.endswith("/android.jar"))
                jar = z.read(name)
    except Exception as e:
        print(f"  Google download failed ({e}); trying the Sable mirror")
    if jar is None:
        level = api or 33
        jar = fetch(SABLE_RAW.format(api=level), f"android.jar {level} (Sable mirror)")
    dest_dir = os.path.join(pdir, f"android-{level}")
    os.makedirs(dest_dir, exist_ok=True)
    with open(os.path.join(dest_dir, "android.jar"), "wb") as f:
        f.write(jar)
    print(f"✓ Android platform {level} saved to {dest_dir}")
    print("  (FlowDroid uses the nearest platform at or above the app's minimum API level.)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", type=int, help="Android platform level to fetch (default: newest)")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    args = ap.parse_args()
    os.makedirs(LIB, exist_ok=True)
    print("LoanWatch tool setup\n")
    check_java()
    get_flowdroid(args.force)
    get_platform(args.api, args.force)
    print("\nDone. Start the web app with:  python3 web/app.py")


if __name__ == "__main__":
    main()
