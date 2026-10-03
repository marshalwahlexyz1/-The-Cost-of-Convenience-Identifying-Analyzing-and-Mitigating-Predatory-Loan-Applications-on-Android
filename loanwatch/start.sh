#!/usr/bin/env bash
# LoanWatch one-click start (macOS / Linux). First run installs everything.
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)
if [ ! -d .venv ]; then
  echo "First run: creating Python environment…"
  "$PY" -m venv .venv
  .venv/bin/pip install --upgrade pip >/dev/null
  .venv/bin/pip install -r requirements.txt
  .venv/bin/python setup_tools.py || echo "Tool download incomplete; FlowDroid will be skipped until setup_tools.py succeeds."
fi
exec .venv/bin/python web/app.py "$@"
