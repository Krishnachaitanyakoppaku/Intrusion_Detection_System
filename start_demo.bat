@echo off
REM IDS System Demo Startup Script for Windows

echo Starting IDS DSL Engine System for Demo...
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: You are not running as Administrator
    echo Packet capture may not work without administrator privileges
    echo.
    echo Choose an option:
    echo   1. Run without admin (may not work)
    echo   2. Exit and restart as Administrator
    echo.
    set /p choice="Enter choice [1-2]: "
    
    if "%choice%"=="2" (
        echo Opening as Administrator...
        powershell -Command "Start-Process python.exe -ArgumentList 'web_server_complete.py' -Verb RunAs"
        exit /b
    )
)

REM Run the web server
python web_server_complete.py

pause



