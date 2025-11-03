@echo off
REM Windows batch script to test IDS components

echo ==========================================
echo Testing IDS Components
echo ==========================================
echo.

set TESTS_PASSED=0
set TESTS_FAILED=0

REM Test 1: Check if required files exist
echo Test 1: Checking required files...
set MISSING_FILES=0

if not exist "scapy_capture.py" (
    echo   Missing: scapy_capture.py
    set /a MISSING_FILES+=1
)
if not exist "src\packet_lexer.l" (
    echo   Missing: src\packet_lexer.l
    set /a MISSING_FILES+=1
)
if not exist "src\packet_parser.y" (
    echo   Missing: src\packet_parser.y
    set /a MISSING_FILES+=1
)
if not exist "src\packet_parser_helper.c" (
    echo   Missing: src\packet_parser_helper.c
    set /a MISSING_FILES+=1
)
if not exist "src\rule_matcher.c" (
    echo   Missing: src\rule_matcher.c
    set /a MISSING_FILES+=1
)
if not exist "src\packet_analyzer.c" (
    echo   Missing: src\packet_analyzer.c
    set /a MISSING_FILES+=1
)
if not exist "src\ast.c" (
    echo   Missing: src\ast.c
    set /a MISSING_FILES+=1
)
if not exist "include\ast.h" (
    echo   Missing: include\ast.h
    set /a MISSING_FILES+=1
)

if %MISSING_FILES%==0 (
    echo [PASS] All required files exist
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] Missing %MISSING_FILES% file(s)
    set /a TESTS_FAILED+=1
)
echo.

REM Test 2: Check Python dependencies
echo Test 2: Checking Python dependencies...
python -c "import scapy" 2>nul
if %ERRORLEVEL%==0 (
    echo [PASS] Scapy library available
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] Scapy library not found
    echo        Install with: pip install scapy
    set /a TESTS_FAILED+=1
)
echo.

REM Test 3: Test Scapy capture script syntax
echo Test 3: Testing Scapy capture script...
python -m py_compile scapy_capture.py 2>nul
if %ERRORLEVEL%==0 (
    echo [PASS] scapy_capture.py syntax is valid
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] scapy_capture.py has syntax errors
    set /a TESTS_FAILED+=1
)
echo.

REM Test 4: Create test log files
echo Test 4: Creating test log files...
if not exist "logs" mkdir logs

echo 2025-11-03 10:00:00 ^| 192.168.1.100:80 -^> 192.168.1.200:443 ^| TCP ^| Size: 150B > logs\test_packets.log
echo 2025-11-03 10:00:01 ^| 192.168.1.101:53 -^> 192.168.1.200:53 ^| UDP ^| Size: 75B >> logs\test_packets.log
echo 2025-11-03 10:00:02 ^| Unknown packet ^| Size: 42B >> logs\test_packets.log

if exist "logs\test_packets.log" (
    echo [PASS] Sample packet log created
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] Failed to create sample log
    set /a TESTS_FAILED+=1
)
echo.

REM Test 5: Check rules file
echo Test 5: Checking rules file...
if exist "rules\local.rules" (
    echo [PASS] Rules file exists
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] Rules file not found
    set /a TESTS_FAILED+=1
)
echo.

REM Test 6: Check log files
echo Test 6: Checking log files...
if not exist "logs\all_packets.log" (
    echo. > logs\all_packets.log
)
if not exist "logs\alerts.log" (
    echo. > logs\alerts.log
)

if exist "logs\all_packets.log" (
    echo [PASS] all_packets.log exists
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] all_packets.log not found
    set /a TESTS_FAILED+=1
)

if exist "logs\alerts.log" (
    echo [PASS] alerts.log exists
    set /a TESTS_PASSED+=1
) else (
    echo [FAIL] alerts.log not found
    set /a TESTS_FAILED+=1
)
echo.

REM Summary
echo ==========================================
echo Test Summary
echo ==========================================
echo Passed: %TESTS_PASSED%
echo Failed: %TESTS_FAILED%
echo.

if %TESTS_FAILED%==0 (
    echo All tests passed!
    echo.
    echo Next steps to test the system:
    echo   1. Run: python scapy_capture.py
    echo   2. Generate some network traffic
    echo   3. Check: logs\all_packets.log for captured packets
) else (
    echo Some tests failed. Please fix the issues above.
)

pause

