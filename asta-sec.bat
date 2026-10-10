@echo off
setlocal
:: asta-sec Windows Runner (Auto-Elevates if not Administrator)
net session >nul 2>&1
if %errorLevel% == 0 (
    "%~dp0asta-sec.exe" %*
) else (
    echo [*] Elevating to Administrator for Npcap packet capture...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~dp0asta-sec.exe\" %*\"' -Verb RunAs"
)
