@echo off
cd /d "%~dp0"
python arp_spoofing_detector.py
if errorlevel 1 (
  echo.
  echo Application did not start. See README.md for Python, Tcl/Tk and dependency setup.
  pause
)
