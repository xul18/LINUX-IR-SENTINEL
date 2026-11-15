@echo off
chcp 65001 >nul
title SENTINEL - Linux IR Console
cd /d "%~dp0"
setlocal

rem Optional overrides: set SENTINEL_PORT=8888 or SENTINEL_NO_BROWSER=1 before running.
set "PORT=%SENTINEL_PORT%"
if "%PORT%"=="" set "PORT=8765"
set "EXTRA="
if not "%SENTINEL_NO_BROWSER%"=="" set "EXTRA=--no-browser"

echo(
echo  ============================================================
echo    SENTINEL // LINUX INCIDENT RESPONSE CONSOLE
echo  ============================================================
echo(

where python >nul 2>nul
if errorlevel 1 (
  echo  [X] Python not found. Install Python 3.9+ and enable "Add to PATH".
  echo      https://www.python.org/downloads/
  pause
  exit /b 1
)

echo  [*] Checking / installing SSH dependency: paramiko ...
python -m pip install -r requirements.txt --disable-pip-version-check -q
if errorlevel 1 (
  echo  [!] Auto-install failed. Console will retry in browser; Demo mode still works.
) else (
  echo  [OK] Dependency ready.
)

echo(
echo  [*] Starting local server on port %PORT% ...
echo  [*] If the port is busy (old console window still open),
echo      the server automatically picks the next free port.
echo  [*] The exact Console URL is printed below and opened in your browser.
echo  [*] Press Ctrl+C or close this window to stop.
echo(
python -u server.py --port %PORT% %EXTRA%
echo(
echo  [*] Service stopped.
pause
