#!/bin/bash

echo "=== IDS System Status Check ==="
echo ""

# Check if web server is running
echo "1. Checking web server..."
if ps aux | grep -v grep | grep -q "web_server_complete.py"; then
    echo "   ✅ Web server is running"
else
    echo "   ❌ Web server is NOT running"
    echo "   Start it with: python3 web_server_complete.py"
fi
echo ""

# Check if IDS engine binaries exist
echo "2. Checking IDS engine binaries..."
if [ -f "bin/ids_engine" ]; then
    echo "   ✅ ids_engine exists"
    ls -lh bin/ids_engine
else
    echo "   ❌ ids_engine NOT found"
    echo "   Build it with: make"
fi

if [ -f "bin/simple_ids" ]; then
    echo "   ✅ simple_ids exists"
else
    echo "   ⚠️  simple_ids NOT found"
fi
echo ""

# Check if IDS process is running
echo "3. Checking if IDS engine is running..."
if ps aux | grep -v grep | grep -q "ids_engine"; then
    echo "   ✅ ids_engine IS running"
    ps aux | grep -v grep | grep "ids_engine"
elif ps aux | grep -v grep | grep -q "simple_ids"; then
    echo "   ⚠️  simple_ids IS running (demo version)"
    ps aux | grep -v grep | grep "simple_ids"
else
    echo "   ❌ IDS engine is NOT running"
    echo "   Start it from web interface or:"
    echo "   sudo ./bin/ids_engine -i YOUR_INTERFACE"
fi
echo ""

# Check network interfaces
echo "4. Available network interfaces:"
ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1"
echo ""

# Check rules file
echo "5. Checking rules file..."
if [ -f "rules/local.rules" ]; then
    RULE_COUNT=$(grep -v "^#" rules/local.rules | grep -v "^$" | wc -l)
    echo "   ✅ rules/local.rules exists"
    echo "   📊 Total rules: $RULE_COUNT"
else
    echo "   ❌ rules/local.rules NOT found"
fi
echo ""

# Check logs
echo "6. Recent alerts (last 10 lines):"
if [ -f "logs/alerts.log" ]; then
    tail -10 logs/alerts.log
else
    echo "   ⚠️  logs/alerts.log doesn't exist yet"
fi
echo ""

# Check firewall monitoring
echo "7. Recent firewall alerts (last 5 lines):"
if [ -f "logs/firewall_monitor.log" ]; then
    tail -5 logs/firewall_monitor.log
else
    echo "   ⚠️  logs/firewall_monitor.log doesn't exist yet"
fi
echo ""

echo "=== Diagnosis Complete ==="
echo ""
echo "Next steps:"
echo "1. If IDS not running: Click 'Start Engine' in web interface"
echo "2. Make sure you selected the CORRECT network interface (not 'lo')"
echo "3. Add rules to 'Current Active Rules' before expecting alerts"
echo "4. Test from ANOTHER computer using: curl \"http://YOUR_SERVER_IP:80/\""
echo ""


