@echo off
echo Starting IDS DSL Engine System...

REM Kill any existing Python processes on port 8080
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8080') do (
    taskkill /PID %%a /F >nul 2>&1
)

REM Start the web server
echo Starting web server with Gemini AI integration...
python web_server_complete.py

pause
