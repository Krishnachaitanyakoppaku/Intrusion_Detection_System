#!/bin/bash
# Quick build script for firewall parser
# Usage: bash build_parser.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building firewall parser (Lex/Yacc)..."
echo ""

# Check for dependencies
if ! command -v flex >/dev/null 2>&1; then
    echo "Error: flex not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y flex bison libfl-dev
fi

if ! command -v bison >/dev/null 2>&1; then
    echo "Error: bison not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y bison flex libfl-dev
fi

# Build
if make; then
    echo ""
    echo " Build successful!"
    echo ""
    echo "Library location: build/firewall/libfirewall_parser.so"
    echo ""
    echo "To test:"
    echo "  python firewall/test_parser.py"
    echo "  Then check web interface at http://localhost:8080"
else
    echo ""
    echo " Build failed. Check errors above."
    exit 1
fi


