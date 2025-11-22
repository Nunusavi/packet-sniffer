@echo off
setlocal
cd /d "%~dp0"
title Packet Sniffer Launcher

:: --- Configuration ---
set "VENV_DIR=env"
set "GEO_DB_FILE=GeoLite2-City.mmdb"
set "GEO_DB_URL=https://git.io/GeoLite2-City.mmdb"

:: --- Admin Check ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo [INFO] Right-click this file and select "Run as Administrator".
    pause
    exit /b 1
)

:: --- Python Check ---
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    pause
    exit /b 1
)

:: --- Setup Virtual Environment ---
:: Check if the python executable specifically exists inside the venv
if not exist ".\%VENV_DIR%\Scripts\python.exe" (
    echo [INFO] Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: --- Verify Venv Creation ---
if not exist ".\%VENV_DIR%\Scripts\python.exe" (
    echo [ERROR] Failed to create Virtual Environment.
    echo [INFO] Please check your Python installation.
    pause
    exit /b 1
)

:: --- Install Dependencies ---
if exist "requirements.txt" (
    echo [INFO] Installing dependencies...
    ".\%VENV_DIR%\Scripts\pip.exe" install -r requirements.txt
) else (
    echo [INFO] Installing default dependencies...
    ".\%VENV_DIR%\Scripts\pip.exe" install flask flask-socketio scapy psutil requests geoip2 waitress
)

:: --- Download GeoIP Database ---
if not exist "%GEO_DB_FILE%" (
    echo [INFO] Downloading GeoIP Database...
    powershell -Command "Invoke-WebRequest -Uri '%GEO_DB_URL%' -OutFile '%GEO_DB_FILE%'"
)

:: --- Run App ---
echo.
echo [SUCCESS] Starting Packet Sniffer...
".\%VENV_DIR%\Scripts\python.exe" app.py

pause