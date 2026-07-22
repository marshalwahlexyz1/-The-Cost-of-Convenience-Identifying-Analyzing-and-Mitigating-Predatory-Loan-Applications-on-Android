# FlowDroid wrappers

These scripts drive [FlowDroid](https://github.com/secure-software-engineering/FlowDroid)
for the taint-analysis stage. FlowDroid itself is **not** vendored in this repo — clone
and build it from upstream, then point the scripts at your build.

```bash
git clone https://github.com/secure-software-engineering/FlowDroid.git
cd FlowDroid && mvn -DskipTests install
# then edit the FLOWDROID_JAR / paths at the top of the run scripts below
```

## Scripts
- `runflowdroid.sh`, `runflowdroid2.sh`, `runflowdroid3.sh` — run FlowDroid over a set of
  APKs and collect source→sink flows.
- `dataflowanalysis.sh` — dataflow-analysis driver used by the LoanApps pipeline.

You will also need a `SourcesAndSinks.txt` (see `../LoanApps/sourcesandsinks.txt`) and an
Android platforms directory (`android-sdk/platforms`).
