@echo off
:: Batch script to elevate and launch Zero-Day Attack Analysis with Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges.
    cd /d "%~dp0backend"
    python app.py
) else (
    echo [INFO] Requesting Administrator privileges for promiscuous packet capture...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d \"%~dp0backend\" && python app.py' -Verb RunAs"
)
