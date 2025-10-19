#!/bin/bash

# IDS DSL Engine - Startup Script
echo "🛡️ Starting IDS DSL Engine System..."

# Kill any existing processes
pkill -f "python3.*web_server" 2>/dev/null || true
pkill -f "simple_ids" 2>/dev/null || true

# Start the web server with Gemini AI integration
echo "🌐 Starting web server with Gemini AI integration..."
python3 web_server_complete.py &

# Wait a moment for server to start
sleep 2

echo "✅ IDS DSL Engine System started!"
echo "🌐 Web Interface: http://localhost:8080"
echo "🤖 Gemini AI Integration: ENABLED"
echo "📋 Rule Management: ENABLED"
echo ""
echo "Press Ctrl+C to stop all services"

# Keep script running
wait
