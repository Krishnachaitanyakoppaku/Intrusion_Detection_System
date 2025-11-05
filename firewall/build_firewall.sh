#!/bin/bash
# Build script for firewall parser that handles WSL/Windows paths

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building firewall parser..."
echo ""

# Install dependencies if needed
if ! command -v flex >/dev/null 2>&1 || ! command -v bison >/dev/null 2>&1; then
    echo "Installing flex and bison..."
    sudo apt-get update -qq
    sudo apt-get install -y flex bison build-essential libfl-dev > /dev/null 2>&1
fi

# Fix line endings if on Windows
if command -v dos2unix >/dev/null 2>&1; then
    echo "Fixing line endings..."
    dos2unix firewall_lexer.l firewall_parser.y firewall_parser_wrapper.c firewall_parser.h 2>/dev/null || true
fi

# Clean and build
echo "Cleaning previous build..."
make clean > /dev/null 2>&1 || true

echo "Building..."
if make; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "Library location: ../build/firewall/libfirewall_parser.so"
    echo ""
    # Test if library exists
    if [ -f "../build/firewall/libfirewall_parser.so" ]; then
        echo "✅ Library file exists"
        ls -lh "../build/firewall/libfirewall_parser.so"
    else
        echo "❌ Library file not found!"
        exit 1
    fi
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi






