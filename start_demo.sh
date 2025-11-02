#!/bin/bash

# IDS System Demo Startup Script
# Handles sudo requirements gracefully

echo "🛡️ Starting IDS DSL Engine System for Demo..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "⚠️  You are not running as root."
    echo "   Packet capture requires sudo privileges."
    echo ""
    echo "Choose an option:"
    echo "  1. Run with sudo now (recommended for demo)"
    echo "  2. Run without sudo (packet capture may not work)"
    echo ""
    read -p "Enter choice [1-2]: " choice
    
    if [ "$choice" == "1" ]; then
        echo "🔐 Switching to sudo..."
        sudo python3 web_server_complete.py
        exit 0
    else
        echo "⚠️  Running without sudo - packet capture may not work"
        python3 web_server_complete.py
        exit 0
    fi
else
    echo "✅ Running as root - no password needed"
    python3 web_server_complete.py
fi


