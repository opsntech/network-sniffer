#!/bin/bash
# Network Sniffer launcher script
# Usage: sudo ./sniff.sh [arguments]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

/opt/homebrew/bin/python3.9 -m network_sniffer.cli "$@"
