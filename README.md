# The Cost of Convenience: Identifying, Analyzing, and Mitigating Predatory Loan Applications on Android

Research artifacts for the paper **"The Cost of Convenience: Identifying, Analyzing, and
Mitigating Predatory Loan Applications on Android"** (Olawale Amos Akanji, Manuel Egele,
and Gianluca Stringhini — ACM ASIA CCS '26, Bangalore, India).

The paper presents the first cross-country measurement of loan-app compliance against
national regulations and Google's Financial Services Policy, analyzing 434 apps from
Indonesia, Kenya, Nigeria, Pakistan, and the Philippines. It translates policy text into
testable permission checks via LLM-assisted policy-to-permission mapping, then combines
static and dynamic analysis of the apps' code and runtime behavior. This repository holds
the analysis pipeline, crawlers, Frida instrumentation, FlowDroid wrappers, and result
data.

## Citation

```bibtex
@inproceedings{akanji2026costofconvenience,
  title     = {The Cost of Convenience: Identifying, Analyzing, and Mitigating
               Predatory Loan Applications on Android},
  author    = {Akanji, Olawale Amos and Egele, Manuel and Stringhini, Gianluca},
  booktitle = {Proceedings of the ACM Asia Conference on Computer and Communications
               Security (ASIA CCS '26)},
  year      = {2026},
  address   = {Bangalore, India},
  publisher = {Association for Computing Machinery},
}
```

## Repository layout

```
loanwatch/      Staged analysis pipeline (policy → audit → API map → static → taint → Frida)
LoanApps/       Corpus-scale analysis scripts, crawlers, and result CSVs
  apkcrawler/     Store crawlers (APKPure, APKMirror, Aptoide, Google Play, …)
  Results/        Sensitive-API / permission / violation reports (CSV, TXT)
frida/          Standalone Frida instrumentation scripts
flowdroid/      Wrapper scripts that drive FlowDroid (the tool itself is NOT vendored)
```

## What is intentionally **not** in this repo

- **APK / app binaries** (`*.apk`, `*.apks`, `*.xapk`, `*.aab`) — not redistributed for
  size and legal/ethical reasons. The analyzed package set is listed in
  `LoanApps/found_packages.csv`; re-fetch from the relevant store or AndroZoo.
- **FlowDroid source** — clone it from upstream (see `flowdroid/README.md`); only our
  wrapper scripts are included here.
- **Regulatory correspondence** — omitted.

## Requirements

- Python 3.8+ (`pip install -r loanwatch/requirements.txt`)
- FlowDroid + Soot (Java 8/11) for the taint-analysis stage
- Frida (host + `frida-server` on a rooted device/emulator) for the dynamic stage
- A Groq API key for the LLM policy/API-mapping stages, provided via the
  `GROQ_API_KEY` environment variable (never hard-code it)

## Pipeline overview (`loanwatch/`)

| Stage | File | Purpose |
|------|------|---------|
| 1 | `stage1_policy.py` | Extract prohibited data categories from a lending policy PDF |
| 2 | `stage2_audit.py`  | Audit the app manifest against those categories |
| 3 | `stage3_api_map.py`| Map prohibited data to guarded Android APIs |
| 4 | `stage4_static.py` | Static scan for those APIs in the app |
| 5 | `stage5_taint.py`  | FlowDroid taint analysis of source→sink flows |
| 6 | `stage6_frida.py`  | Frida runtime confirmation of exfiltration |

See `LoanApps/PIPELINE.md` for the corpus-scale variant.

## Web app (single-app audits, e.g. for journalists)

`loanwatch/web/` wraps stages 1–6 in a local web page: upload an APK and a
policy PDF, review the AI-extracted prohibited permissions (with supporting
quotes), and get the manifest audit, bytecode locations, FlowDroid paths,
embedded trackers and a Frida script for on-device confirmation.

```bash
cd loanwatch
./start.sh          # Windows: start.bat — installs deps, downloads FlowDroid + android.jar, opens the page
```

See [`loanwatch/JOURNALIST_GUIDE.md`](loanwatch/JOURNALIST_GUIDE.md) for setup and how to read the results.
