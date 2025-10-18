#!/bin/bash

# IDS DSL Engine - One Command Launcher
# This script does everything automatically

echo "🛡️  IDS DSL Engine - Smart Security System"
echo "=========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "setup_and_run.sh" ]; then
    echo "❌ Error: Please run this script from the IDS DSL Engine project directory"
    exit 1
fi

# Make sure the setup script is executable
chmod +x setup_and_run.sh

# Run the complete setup and launch
echo "🚀 Starting IDS DSL Engine..."
echo "This will:"
echo "  • Install all dependencies"
echo "  • Build the project"
echo "  • Start the web interface"
echo "  • Open your browser automatically"
echo ""
echo "Press Enter to continue or Ctrl+C to cancel..."
read

# Run the setup script
./setup_and_run.sh
