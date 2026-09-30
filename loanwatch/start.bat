@echo off
REM LoanWatch one-click start (Windows). First run installs everything.
cd /d "%~dp0"
if not exist .venv (
  echo First run: creating Python environment...
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\python -m pip install --upgrade pip
  .venv\Scripts\pip install -r requirements.txt
  .venv\Scripts\python setup_tools.py
)
.venv\Scripts\python web\app.py %*
