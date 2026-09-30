# LoanWatch web app: setup and use

LoanWatch checks an Android loan app against a lending policy. You upload the
app (`.apk`) and the policy (PDF), and the page tells you:

1. **What the policy prohibits.** An AI reads the policy and lists the phone
   data it bans (contacts, call logs, photos…) as Android permissions, quoting
   the sentences it relied on. You check and edit that list before anything runs.
2. **Whether the app asks for that data.** These are the permissions it
   declares in its manifest.
3. **Where its code reads the data.** Androguard scans the app's bytecode.
4. **Whether the data can flow to the network.** FlowDroid does a taint
   analysis, which takes a few minutes.
5. **Which tracking SDKs are embedded.** These are matched against Exodus
   Privacy signatures.
6. **A Frida script** for the last step, the on-device test, which can't run
   in a browser.

Everything runs on your own computer. The APK is never uploaded anywhere. When
the AI is on, only the policy text and the app's permission and method names
are sent to Groq.

The method comes from *The Cost of Convenience: Identifying, Analyzing, and
Mitigating Predatory Loan Applications on Android* (Akanji, Egele, Stringhini,
ACM ASIA CCS '26, [arXiv:2601.12634](https://arxiv.org/abs/2601.12634)).

---

## 1. Install (once)

You need:

| What | Why | Where |
|---|---|---|
| Python 3.9+ | runs the app | https://www.python.org/downloads/ (Windows: tick "Add to PATH") |
| Java 11+ | runs FlowDroid | https://adoptium.net (Temurin, LTS) |
| Groq API key | the AI steps | free at https://console.groq.com/keys |
| ~2 GB disk, 8 GB+ RAM | FlowDroid | |

Then get the code:

```bash
git clone https://github.com/marshalwahlexyz1/-The-Cost-of-Convenience-Identifying-Analyzing-and-Mitigating-Predatory-Loan-Applications-on-Android.git loanwatch-repo
cd loanwatch-repo/loanwatch
```

## 2. Start it

- **macOS / Linux:** `./start.sh`
- **Windows:** double-click `start.bat`

The first start takes a few minutes. It creates a private Python environment,
installs the Python libraries (Androguard, Groq, PyMuPDF, Flask) and runs
`setup_tools.py`, which downloads:

- FlowDroid 2.15.1 from Maven Central into `lib/flowdroid.jar`, with its checksum verified
- the newest Android SDK platform (`android.jar`) from Google into `lib/platforms/`

After that, your browser opens **http://127.0.0.1:8765**. Later starts are instant.

On the page, paste your Groq key in the setup box and click **Save on this
computer**. It is stored in `loanwatch/.env`, which never leaves your machine.

The setup box shows a green tick for each tool. If FlowDroid or the Android
platform shows a cross, run `python setup_tools.py` again (inside the
`.venv`) and read its message.

## 3. Check an app

1. **Upload** the `.apk` and the policy PDF, then click **Read policy and open app**.
   - Under *Options* you can name the regulator (e.g. "Kenyan") or give a
     clause number. If you leave the clause blank, the AI reads the whole policy.
   - `.xapk` / `.apks` bundles: unzip them and upload `base.apk`.
2. **Check the list.** The AI's prohibited permissions are ticked, with the
   quotes it relied on. Permissions the app declares have a red **declared**
   tag. Untick anything the policy doesn't ban, or add more. The presets
   (Google Play, Kenya, Nigeria, Pakistan, Philippines) are the permission sets
   used in the paper.
3. **Run the checks.** With FlowDroid this takes about 1–10 minutes depending
   on the app's size. You can watch each step, and the technical log is there
   if something fails.
4. **Read the report.** You can print it or save it as PDF, download the full
   JSON, and download the Frida script(s).

Past reports stay available under **Past reports**. They are saved in `web/jobs/`.

## 4. How to read the results

- **"Violates the policy"** means the app *declares* a prohibited permission.
  That is a documented fact about the app, but it does not prove the app used it.
- **"Where the code reads the data"** shows the app code that calls the
  Android APIs for that data. That is strong evidence the app is built to read it.
- **FlowDroid paths** mean static analysis found a route from that data to a
  network call. If FlowDroid finds *no* path, that does **not** prove the app
  doesn't send the data. Static analysis misses flows through obfuscation,
  reflection, native code and some libraries.
- **Only the on-device test shows what the app actually does.**

## 5. On-device test (dynamic analysis)

This step runs outside the browser. In the paper it was done on a test
device: launch the app and answer its permission prompts only, **before
registering**. The notable finding was apps sending contacts, SMS, location
or media before sign-up.

You need a **test** Android phone or emulator that you control and are
willing to wipe. Use a rooted device or an emulator image with root access
(a "Google APIs" image, not "Google Play"). Fill it with **dummy** contacts,
SMS and photos. Never use a phone with real people's data on it.

```bash
pip install frida-tools
# install frida-server on the device: https://frida.re/docs/android/
adb install base.apk
frida -U -f <package.name> -l loanwatch_frida.js -o frida_log.txt
```

The report page shows the exact command for the app you checked. In the log:

- `[LW][DATA-ACCESS]`: the app opened contacts, SMS, call logs or media
- `[LW][APP …]`: one of the methods the report flagged ran, with its arguments and return value
- `[LW][NET]`: a URL the app connected to

`loanwatch_frida.js` is built directly from the report, so it always loads.
If the AI is on, you also get `loanwatch_frida_ai.js`, a script the AI wrote
with more targeted hooks. It can occasionally need a small fix.

## Troubleshooting

| Problem | Fix |
|---|---|
| "AI step failed" | Check the key and your internet connection. The Groq free tier is rate-limited, so wait a minute and retry. You can also tick the permissions by hand; the rest still works. |
| FlowDroid "did not finish" | The app is large. Close other programs, or set `LOANWATCH_JAVA_MEM=6g` (or higher) before starting. FlowDroid gives up after about 8 minutes by design. |
| "No code calling the matching Android APIs was found" | The app may hide its code (packing, native libraries). The on-device test is the way to check. |
| Port 8765 busy | Run `./start.sh --port 8800` |
