@echo off
REM IDS Engine Check - Build and Run Analyzer (Windows launcher)
REM Uses WSL for building and running the analyzer

setlocal ENABLEDELAYEDEXPANSION

echo ==========================================
echo IDS Engine Check (Build + Run)
echo ==========================================
echo.

REM Move to script directory
cd /d "%~dp0"

REM Verify WSL is available
where wsl >nul 2>nul
if errorlevel 1 (
  echo [ERROR] WSL not found. Please install WSL or build using MSYS2/MinGW.
  exit /b 1
)

echo [1/2] Building packet_analyzer via WSL...
wsl -e bash -lc "cd '$(wslpath '%CD%')' && make packet_analyzer"
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo.
echo [2/2] Running analyzer...
wsl -e bash -lc "cd '$(wslpath '%CD%')' && ./bin/packet_analyzer logs/all_packets.log rules/active.rules"
set EXITCODE=%ERRORLEVEL%

echo.
if %EXITCODE% EQU 0 (
  echo [DONE] Analyzer completed. See logs\alerts.log
) else (
  echo [DONE] Analyzer exited with code %EXITCODE%.
)

endlocal
exit /b %EXITCODE%


