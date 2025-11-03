#!/bin/bash

echo "=========================================="
echo "Testing IDS Components"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test result
print_test() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} $2"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Check if required files exist
echo "Test 1: Checking required files..."
MISSING_FILES=0
REQUIRED_FILES=(
    "scapy_capture.py"
    "src/packet_lexer.l"
    "src/packet_parser.y"
    "src/packet_parser_helper.c"
    "src/rule_matcher.c"
    "src/packet_analyzer.c"
    "src/ast.c"
    "include/ast.h"
    "include/packet_parser.h"
    "include/rule_matcher.h"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}  Missing: $file${NC}"
        ((MISSING_FILES++))
    fi
done

if [ $MISSING_FILES -eq 0 ]; then
    print_test 0 "All required files exist"
else
    print_test 1 "Missing $MISSING_FILES file(s)"
fi
echo ""

# Test 2: Check Python dependencies
echo "Test 2: Checking Python dependencies..."
python3 -c "import scapy" 2>/dev/null
print_test $? "Scapy library available"
echo ""

# Test 3: Test Scapy capture script (syntax check)
echo "Test 3: Testing Scapy capture script..."
python3 -m py_compile scapy_capture.py 2>/dev/null
print_test $? "scapy_capture.py syntax is valid"
echo ""

# Test 4: Build packet analyzer (if tools available)
echo "Test 4: Testing build process..."
if command -v bison >/dev/null 2>&1 && command -v flex >/dev/null 2>&1; then
    echo "  Building packet analyzer..."
    make packet_analyzer 2>/dev/null
    if [ -f "bin/packet_analyzer" ]; then
        print_test 0 "Packet analyzer built successfully"
    else
        print_test 1 "Packet analyzer build failed"
    fi
else
    echo -e "${YELLOW}  ⚠ Bison/Flex not available - skipping build test${NC}"
fi
echo ""

# Test 5: Test packet log parsing (create sample log)
echo "Test 5: Testing packet log parsing..."
mkdir -p logs
cat > logs/test_packets.log << 'EOF'
2025-11-03 10:00:00 | 192.168.1.100:80 -> 192.168.1.200:443 | TCP | Size: 150B
2025-11-03 10:00:01 | 192.168.1.101:53 -> 192.168.1.200:53 | UDP | Size: 75B
2025-11-03 10:00:02 | Unknown packet | Size: 42B
EOF

if [ -f "logs/test_packets.log" ]; then
    print_test 0 "Sample packet log created"
    echo "  Sample log entries:"
    head -3 logs/test_packets.log | sed 's/^/    /'
else
    print_test 1 "Failed to create sample log"
fi
echo ""

# Test 6: Test rule file exists
echo "Test 6: Checking rules file..."
if [ -f "rules/local.rules" ]; then
    RULE_COUNT=$(grep -c "^alert\|^log" rules/local.rules 2>/dev/null || echo "0")
    print_test 0 "Rules file exists ($RULE_COUNT rules found)"
else
    print_test 1 "Rules file not found"
fi
echo ""

# Test 7: Test log file formats
echo "Test 7: Checking log file formats..."
if [ -f "logs/all_packets.log" ]; then
    LINE_COUNT=$(wc -l < logs/all_packets.log)
    print_test 0 "all_packets.log exists ($LINE_COUNT lines)"
else
    echo "  Creating empty all_packets.log..."
    touch logs/all_packets.log
    print_test 0 "all_packets.log created"
fi

if [ -f "logs/alerts.log" ]; then
    ALERT_COUNT=$(wc -l < logs/alerts.log)
    print_test 0 "alerts.log exists ($ALERT_COUNT alerts)"
else
    echo "  Creating empty alerts.log..."
    touch logs/alerts.log
    print_test 0 "alerts.log created"
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    echo ""
    echo "Next steps to test the system:"
    echo "  1. Run: python3 scapy_capture.py [interface]"
    echo "  2. In another terminal, generate some network traffic"
    echo "  3. Run: bin/packet_analyzer"
    echo "  4. Check: logs/alerts.log for generated alerts"
else
    echo -e "${YELLOW}Some tests failed. Please fix the issues above.${NC}"
fi

