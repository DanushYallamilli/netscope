#!/bin/bash
# NetScope launcher for macOS and Linux.
# Run with sudo for ARP scanning:   sudo ./start-mac-linux.sh
# Without sudo it still works, using a ping sweep + the ARP table instead.
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -r requirements.txt --quiet
python run.py "$@"
