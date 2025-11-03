#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "IDS Engine Check (Build + Run)"
echo "=========================================="
echo

cd "$(dirname "$0")"

echo "[1/2] Building packet_analyzer..."
make packet_analyzer

echo
echo "[2/2] Running analyzer..."
./bin/packet_analyzer logs/all_packets.log rules/active.rules

echo
echo "[DONE] Analyzer finished. See logs/alerts.log"


