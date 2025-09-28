#!/bin/bash
set -e
# This script must be run with sudo to capture packets.
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo: sudo ./run.sh"
  exit 1
fi
echo "Activating virtual environment and starting the application..."
source "/home/nunusavi/packet-sniffer/env/bin/activate"
/usr/bin/python3 app.py
